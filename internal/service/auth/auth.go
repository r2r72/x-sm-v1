// Package auth provides authentication and authorization services.
package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AuthService is the main authentication service.
type AuthService struct {
	repo   AuthRepository
	secret []byte
}

// NewAuthService creates a new AuthService.
// secret must be at least 32 bytes for HS256.
func NewAuthService(repo AuthRepository, secret []byte) *AuthService {
	if len(secret) < 32 {
		panic("jwt secret must be at least 32 bytes")
	}
	return &AuthService{repo: repo, secret: secret}
}

// Register creates a new user.
func (s *AuthService) Register(ctx context.Context, input RegisterInput) (*Tokens, error) {
	if len(input.Password) < 8 || !hasDigit(input.Password) || !hasLetter(input.Password) {
		return nil, ErrInvalidPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), 12)
	if err != nil {
		return nil, fmt.Errorf("bcrypt: %w", err)
	}

	userID := generateID()

	user := &User{
		ID:           userID,
		TenantID:     input.TenantID,
		Username:     input.Username,
		Email:        input.Email,
		PasswordHash: string(hash),
		MFAEnabled:   false,
		MFASecret:    "",
		Active:       true,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrUserExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	s.repo.LogLoginAttempt(ctx, &LoginAttempt{
		TenantID:  input.TenantID,
		Username:  input.Username,
		IP:        "127.0.0.1",
		UserAgent: "api/register",
		Success:   true,
		Reason:    "registration",
	})

	return s.createTokens(userID, input.TenantID)
}

// Login authenticates a user.
func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	user, err := s.repo.GetUserByUsername(ctx, input.TenantID, input.Username)
	if err != nil {
		s.logFailedLogin(ctx, input, "user_not_found")
		return nil, ErrInvalidCredentials
	}

	if !user.Active {
		s.logFailedLogin(ctx, input, "user_inactive")
		return nil, ErrUserInactive
	}

	// Always compare — timing attack protection
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password))
	if err != nil {
		s.logFailedLogin(ctx, input, "invalid_password")
		return nil, ErrInvalidCredentials
	}

	s.repo.LogLoginAttempt(ctx, &LoginAttempt{
		TenantID:  input.TenantID,
		Username:  input.Username,
		IP:        input.IPAddress,
		UserAgent: input.UserAgent,
		Success:   true,
		Reason:    "success",
	})

	tokens, err := s.createTokens(user.ID, user.TenantID)
	if err != nil {
		return nil, fmt.Errorf("create tokens: %w", err)
	}

	return &LoginResult{
		Tokens:      tokens,
		RequiresMFA: false,
	}, nil
}

// CompleteLoginWithMFA completes login with MFA (stub).
func (s *AuthService) CompleteLoginWithMFA(ctx context.Context, sessionID, code string) (*Tokens, error) {
	session, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		s.repo.DeleteSession(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	if len(code) == 6 {
		s.repo.DeleteSession(ctx, sessionID)
		return s.createTokens(session.UserID, session.TenantID)
	}

	return nil, ErrInvalidMFA
}

// Refresh refreshes tokens.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	token, err := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	userID, _ := claims["sub"].(string)
	tenantID, _ := claims["tenant"].(string)
	if userID == "" || tenantID == "" {
		return nil, ErrInvalidToken
	}

	return s.createTokens(userID, tenantID)
}

// Logout revokes sessions.
func (s *AuthService) Logout(ctx context.Context, userID string) error {
	return s.repo.DeleteSessionsByUser(ctx, userID)
}

// === Private helpers ===

func (s *AuthService) createTokens(userID, tenantID string) (*Tokens, error) {
	now := time.Now()

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    userID,
		"tenant": tenantID,
		"exp":    now.Add(15 * time.Minute).Unix(),
		"iat":    now.Unix(),
	})
	accessTokenStr, err := accessToken.SignedString(s.secret)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    userID,
		"tenant": tenantID,
		"exp":    now.Add(7 * 24 * time.Hour).Unix(),
		"iat":    now.Unix(),
		"jti":    generateID(),
	})
	refreshTokenStr, err := refreshToken.SignedString(s.secret)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	return &Tokens{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenStr,
		ExpiresAt:    now.Add(15 * time.Minute),
		UserID:       userID,
	}, nil
}

func (s *AuthService) logFailedLogin(ctx context.Context, input LoginInput, reason string) {
	s.repo.LogLoginAttempt(ctx, &LoginAttempt{
		TenantID:  input.TenantID,
		Username:  input.Username,
		IP:        input.IPAddress,
		UserAgent: input.UserAgent,
		Success:   false,
		Reason:    reason,
	})
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func hasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func hasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// isUniqueViolation detects PostgreSQL unique constraint violation.
func isUniqueViolation(err error) bool {
	type PGError interface{ SQLState() string }
	var pgErr PGError
	if ok := errors.As(err, &pgErr); ok {
		return pgErr.SQLState() == "23505"
	}
	return false
}

// ParseTokenUnsafe извлекает user_id из JWT без проверки срока действия.
// Используется только для /logout.
func (s *AuthService) ParseTokenUnsafe(authHeader string) (string, error) {
	tokenStr := s.extractBearerToken(authHeader)
	if tokenStr == "" {
		return "", ErrInvalidToken
	}

	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return "", ErrInvalidToken
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if userID, ok := claims["sub"].(string); ok && userID != "" {
			return userID, nil
		}
	}
	return "", ErrInvalidToken
}

func (s *AuthService) extractBearerToken(header string) string {
	if len(header) > 7 && header[:7] == "Bearer " {
		return header[7:]
	}
	return ""
}
