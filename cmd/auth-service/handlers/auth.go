// Package handlers содержит HTTP-обработчики для аутентификации.
//
// Все эндпоинты:
//
//	POST /register      — регистрация нового пользователя
//	POST /login         — вход по логину/паролю (этап 1)
//	POST /login/mfa     — подтверждение MFA (этап 2)
//	POST /refresh       — обновление токена
//	POST /logout        — выход (отзыв сессии)
//
// Безопасность:
//   - Rate limiting (не в этом файле, но в API Gateway)
//   - CORS (настраивается в Traefik/Nginx)
//   - Все ответы в формате JSON: { "error": "...", "data": {...} }
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/r2r72/x-sm-v1/internal/service"
)

// RegisterAuthRoutes регистрирует все маршруты аутентификации.
func RegisterAuthRoutes(mux *http.ServeMux, svc *service.AuthService) {
	mux.HandleFunc("POST /register", withError(handleRegister(svc)))
	mux.HandleFunc("POST /login", withError(handleLogin(svc)))
	mux.HandleFunc("POST /login/mfa", withError(handleLoginMFA(svc)))
	mux.HandleFunc("POST /refresh", withError(handleRefresh(svc)))
	mux.HandleFunc("POST /logout", withError(handleLogout(svc)))
}

// withError оборачивает обработчик, чтобы ловить паники и возвращать 500.
func withError(h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			log.Printf("⚠️ HTTP error: %v", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		}
	}
}

// === Типы запросов и ответов ===

// RegisterRequest — данные для регистрации.
type RegisterRequest struct {
	TenantID string `json:"tenant_id"` // Обязательно для multi-tenancy
	Username string `json:"username"`  // Логин (может быть email)
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"` // Для синхронизации в objects
}

// LoginRequest — данные для входа.
type LoginRequest struct {
	TenantID string `json:"tenant_id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// MFARequest — подтверждение MFA.
type MFARequest struct {
	SessionID string `json:"session_id"` // Возвращается на этапе /login
	Code      string `json:"code"`       // 6-значный TOTP-код
}

// TokenResponse — успешный ответ с токенами.
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	UserID       string    `json:"user_id"`
}

// === Обработчики ===

// handleRegister обрабатывает регистрацию нового пользователя.
// Тело запроса: JSON с RegisterRequest.
// Успешный ответ (201): TokenResponse.
// Ошибки: 400 (валидация), 409 (пользователь существует), 500.
func handleRegister(svc *service.AuthService) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return nil
		}

		// Валидация входных данных
		if req.TenantID == "" || req.Username == "" || req.Password == "" {
			http.Error(w, `{"error":"tenant_id, username and password are required"}`, http.StatusBadRequest)
			return nil
		}

		// Регистрация
		tokens, err := svc.Register(r.Context(), service.RegisterInput{
			TenantID: req.TenantID,
			Username: req.Username,
			Email:    req.Email,
			Password: req.Password,
			UserData: map[string]interface{}{ // Для синхронизации в objects
				"full_name": req.FullName,
				"email":     req.Email,
				"roles":     []string{"user"},
			},
		})
		if err != nil {
			switch err {
			case service.ErrUserExists:
				http.Error(w, `{"error":"user already exists"}`, http.StatusConflict)
				return nil
			case service.ErrInvalidPassword:
				http.Error(w, `{"error":"password too weak"}`, http.StatusBadRequest)
				return nil
			default:
				return err // 500
			}
		}

		w.WriteHeader(http.StatusCreated)
		return json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			ExpiresAt:    tokens.ExpiresAt,
			UserID:       tokens.UserID,
		})
	}
}

// handleLogin — первый этап входа (логин/пароль).
// Если MFA включён — возвращает session_id и требует /login/mfa.
// Если нет — сразу выдаёт токены.
func handleLogin(svc *service.AuthService) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return nil
		}

		if req.TenantID == "" || req.Username == "" || req.Password == "" {
			http.Error(w, `{"error":"tenant_id, username and password are required"}`, http.StatusBadRequest)
			return nil
		}

		result, err := svc.Login(r.Context(), service.LoginInput{
			TenantID:  req.TenantID,
			Username:  req.Username,
			Password:  req.Password,
			IPAddress: r.RemoteAddr,
			UserAgent: r.UserAgent(),
		})
		if err != nil {
			switch err {
			case service.ErrInvalidCredentials:
				http.Error(w, `{"error":"invalid username or password"}`, http.StatusUnauthorized)
				return nil
			case service.ErrUserInactive:
				http.Error(w, `{"error":"user account is inactive"}`, http.StatusForbidden)
			default:
				return err
			}
		}

		if result.RequiresMFA {
			// Этап 1: ждём MFA
			w.WriteHeader(http.StatusPartialContent) // 206
			return json.NewEncoder(w).Encode(map[string]string{
				"session_id": result.SessionID,
				"message":    "mfa required",
			})
		}

		// Этап 2: сразу выдаём токены
		return json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  result.Tokens.AccessToken,
			RefreshToken: result.Tokens.RefreshToken,
			ExpiresAt:    result.Tokens.ExpiresAt,
			UserID:       result.Tokens.UserID,
		})
	}
}

// handleLoginMFA — подтверждение входа через MFA (TOTP).
// Тело: { "session_id": "...", "code": "123456" }
// Успешно: 200 + TokenResponse.
func handleLoginMFA(svc *service.AuthService) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req MFARequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return nil
		}

		tokens, err := svc.CompleteLoginWithMFA(r.Context(), req.SessionID, req.Code)
		if err != nil {
			switch err {
			case service.ErrInvalidMFA:
				http.Error(w, `{"error":"invalid mfa code"}`, http.StatusUnauthorized)
				return nil
			case service.ErrSessionExpired:
				http.Error(w, `{"error":"session expired"}`, http.StatusGone)
				return nil
			default:
				return err
			}
		}

		return json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			ExpiresAt:    tokens.ExpiresAt,
			UserID:       tokens.UserID,
		})
	}
}

// handleRefresh — обновление access-токена по refresh-токену.
// Тело: { "refresh_token": "..." }
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func handleRefresh(svc *service.AuthService) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return nil
		}

		tokens, err := svc.Refresh(r.Context(), req.RefreshToken)
		if err != nil {
			switch err {
			case service.ErrInvalidToken:
				http.Error(w, `{"error":"invalid refresh token"}`, http.StatusUnauthorized)
				return nil
			default:
				return err
			}
		}

		return json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			ExpiresAt:    tokens.ExpiresAt,
			UserID:       tokens.UserID,
		})
	}
}

// handleLogout — выход: отзыв текущей сессии.
// Тело: { "refresh_token": "..." } (опционально)
// Без тела — отзыв всех сессий пользователя (требует access-токен в заголовке).
func handleLogout(svc *service.AuthService) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"authorization header required"}`, http.StatusUnauthorized)
			return nil
		}

		// Извлекаем user_id из access-токена (без проверки срока — для выхода можно expired)
		userID, err := svc.ParseTokenUnsafe(authHeader)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return nil
		}

		if err := svc.Logout(r.Context(), userID); err != nil {
			return err
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}
