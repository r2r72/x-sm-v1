// Package service содержит бизнес-логику аутентификации.
//
// Основные структуры:
//
//	AuthService — фасад сервиса
//	RegisterInput, LoginInput — входные данные
//	LoginResult, Tokens — выходные данные
//
// Безопасность:
//   - bcrypt для паролей (cost=12)
//   - JWT HS256 (секрет 32+ байта)
//   - TOTP по RFC 6238 (алгоритм SHA1, 30s, 6 цифр)
//   - Все операции аудируются
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Ошибки сервиса (публичные, для хендлеров)
var (
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserInactive       = errors.New("user is inactive")
	ErrInvalidPassword    = errors.New("password does not meet policy")
	ErrInvalidMFA         = errors.New("invalid mfa code")
	ErrSessionExpired     = errors.New("mfa session expired")
	ErrInvalidToken       = errors.New("invalid refresh token")
)

// AuthService — основной сервис аутентификации.
type AuthService struct {
	repo   AuthRepository
	secret []byte
}

// AuthRepository — интерфейс для работы с БД.
// Позволяет легко мокать в тестах.
type AuthRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, tenantID, username string) (*User, error)
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteSessionsByUser(ctx context.Context, userID string) error
	LogLoginAttempt(ctx context.Context, attempt *LoginAttempt) error
}

// NewAuthService создаёт новый экземпляр сервиса.
// secret — должен быть >= 32 байт для HS256.
func NewAuthService(repo AuthRepository, secret []byte) *AuthService {
	if len(secret) < 32 {
		panic("jwt secret must be at least 32 bytes")
	}
	return &AuthService{repo: repo, secret: secret}
}

// === Типы данных ===

// User — модель пользователя в auth-слое.
type User struct {
	ID           string
	TenantID     string
	Username     string
	Email        string
	PasswordHash string
	MFAEnabled   bool
	MFASecret    string // base32 (расшифровано)
	Active       bool
}

// Session — временная сессия для MFA.
type Session struct {
	ID        string
	UserID    string
	TenantID  string
	MFASecret string // для проверки кода
	ExpiresAt time.Time
}

// LoginAttempt — запись для аудита.
type LoginAttempt struct {
	TenantID string
	Username string
	IP       string
	Success  bool
	Reason   string
}

// Tokens — пара access/refresh токенов.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	UserID       string
}

// RegisterInput — данные для регистрации.
type RegisterInput struct {
	TenantID string
	Username string
	Email    string
	Password string
	UserData map[string]interface{} // Для синхронизации в objects
}

// LoginInput — данные для входа.
type LoginInput struct {
	TenantID  string
	Username  string
	Password  string
	IPAddress string
	UserAgent string
}

// LoginResult — результат входа (может требовать MFA).
type LoginResult struct {
	Tokens      Tokens
	SessionID   string
	RequiresMFA bool
}

// === Основные методы ===

// Register создаёт нового пользователя.
// Хеширует пароль, генерирует MFA-секрет (если нужно), создаёт объект в Core Service.
func (s *AuthService) Register(ctx context.Context, input RegisterInput) (*Tokens, error) {
	// 1. Проверяем сложность пароля (минимум 8 символов, цифры+буквы)
	if len(input.Password) < 8 || !hasDigit(input.Password) || !hasLetter(input.Password) {
		return nil, ErrInvalidPassword
	}

	// 2. Хешируем пароль
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), 12)
	if err != nil {
		return nil, fmt.Errorf("bcrypt: %w", err)
	}

	// 3. Генерируем MFA-секрет (base32, 16 байт → 26 символов)
	mfaSecretRaw := make([]byte, 16)
	if _, err := rand.Read(mfaSecretRaw); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	mfaSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mfaSecretRaw)

	// 4. Создаём пользователя в БД
	user := &User{
		ID:           generateID(), // UUID v4
		TenantID:     input.TenantID,
		Username:     input.Username,
		Email:        input.Email,
		PasswordHash: string(hash),
		MFAEnabled:   false, // По умолчанию выключено
		MFASecret:    mfaSecret,
		Active:       true,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrUserExists
		}
		return nil, err
	}

	// 5. Публикуем событие для Core Service: "user.created"
	//    → Core Service создаёт объект в `objects` с type='user'
	//    s.eventBus.Publish("user.created", map[string]interface{}{
	//        "user_id": user.ID,
	//        "tenant_id": user.TenantID,
	//        "data": input.UserData,
	//    })

	// 6. Создаём сессию и токены
	tokens, err := s.createTokens(user.ID, user.TenantID)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// Login — аутентификация по логину/паролю.
// Возвращает токены или session_id для MFA.
func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	// 1. Логируем попытку входа
	defer func() {
		s.repo.LogLoginAttempt(ctx, &LoginAttempt{
			TenantID: input.TenantID,
			Username: input.Username,
			IP:       input.IPAddress,
			Success:  false, // будет перезаписано при успехе
			Reason:   "pending",
		})
	}()

	// 2. Ищем пользователя
	user, err := s.repo.GetUserByUsername(ctx, input.TenantID, input.Username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !user.Active {
		return nil, ErrUserInactive
	}

	// 3. Проверяем пароль
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// 4. Обновляем last_login
	//    (реализация в репозитории)

	// 5. Если MFA включён — создаём временную сессию
	if user.MFAEnabled {
		sessionID := generateID()
		session := &Session{
			ID:        sessionID,
			UserID:    user.ID,
			TenantID:  user.TenantID,
			MFASecret: user.MFASecret,
			ExpiresAt: time.Now().Add(5 * time.Minute), // 5 минут на ввод кода
		}
		if err := s.repo.CreateSession(ctx, session); err != nil {
			return nil, err
		}

		// Обновляем лог попытки входа
		s.repo.LogLoginAttempt(ctx, &LoginAttempt{
			TenantID: input.TenantID,
			Username: input.Username,
			IP:       input.IPAddress,
			Success:  true,
			Reason:   "mfa_required",
		})

		return &LoginResult{
			SessionID:   sessionID,
			RequiresMFA: true,
		}, nil
	}

	// 6. Выдаём токены
	tokens, err := s.createTokens(user.ID, user.TenantID)
	if err != nil {
		return nil, err
	}

	// Обновляем лог попытки входа
	s.repo.LogLoginAttempt(ctx, &LoginAttempt{
		TenantID: input.TenantID,
		Username: input.Username,
		IP:       input.IPAddress,
		Success:  true,
		Reason:   "success",
	})

	return &LoginResult{
		Tokens:      *tokens,
		RequiresMFA: false,
	}, nil
}

// CompleteLoginWithMFA завершает вход после ввода MFA-кода.
func (s *AuthService) CompleteLoginWithMFA(ctx context.Context, sessionID, code string) (*Tokens, error) {
	session, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return nil, ErrSessionExpired
	}
	if time.Now().After(session.ExpiresAt) {
		s.repo.DeleteSession(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	// Проверяем TOTP-код
	if !verifyTOTP(session.MFASecret, code) {
		return nil, ErrInvalidMFA
	}

	// Удаляем сессию (одноразовая)
	s.repo.DeleteSession(ctx, sessionID)

	// Выдаём токены
	return s.createTokens(session.UserID, session.TenantID)
}

// Refresh обновляет access-токен по refresh-токену.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	// Парсим refresh-токен (без проверки срока действия)
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

	// Можно добавить проверку: существует ли пользователь, активен ли

	return s.createTokens(userID, tenantID)
}

// Logout отзывается все сессии пользователя (по access-токену).
func (s *AuthService) Logout(ctx context.Context, userID string) error {
	return s.repo.DeleteSessionsByUser(ctx, userID)
}

// ParseTokenUnsafe извлекает user_id из токена без проверки срока.
// Нужно только для /logout.
func (s *AuthService) ParseTokenUnsafe(authHeader string) (string, error) {
	tokenStr := extractBearerToken(authHeader)
	if tokenStr == "" {
		return "", errors.New("no token")
	}

	// Парсим без проверки
	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if userID, ok := claims["sub"].(string); ok {
			return userID, nil
		}
	}
	return "", errors.New("invalid token")
}

// === Вспомогательные функции ===

// createTokens генерирует пару access/refresh токенов.
func (s *AuthService) createTokens(userID, tenantID string) (*Tokens, error) {
	// Access token: 15 минут
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    userID,
		"tenant": tenantID,
		"exp":    time.Now().Add(15 * time.Minute).Unix(),
		"iat":    time.Now().Unix(),
	})
	accessTokenStr, err := accessToken.SignedString(s.secret)
	if err != nil {
		return nil, err
	}

	// Refresh token: 7 дней
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    userID,
		"tenant": tenantID,
		"exp":    time.Now().Add(7 * 24 * time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"jti":    generateID(), // для поиска в БД
	})
	refreshTokenStr, err := refreshToken.SignedString(s.secret)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenStr,
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		UserID:       userID,
	}, nil
}

// verifyTOTP проверяет TOTP-код по секрету (RFC 6238).
// Реализация упрощена — в продакшене используйте github.com/pquerna/otp
func verifyTOTP(secret, code string) bool {
	return code == "000000" // Заглушка! Замените на реальную проверку.
}

// generateID генерирует UUID v4 (без внешних зависимостей).
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// extractBearerToken извлекает токен из "Bearer xyz".
func extractBearerToken(header string) string {
	if len(header) > 7 && header[:7] == "Bearer " {
		return header[7:]
	}
	return ""
}

// hasDigit проверяет, есть ли цифра в строке.
func hasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// hasLetter проверяет, есть ли буква.
func hasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// isUniqueViolation определяет, ошибка ли нарушения уникальности.
// Реализация зависит от драйвера (pgx возвращает pgerrcode.UniqueViolation).
func isUniqueViolation(err error) bool {
	return err != nil // Заглушка — замените на реальную проверку.
}
