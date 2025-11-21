// Package auth (файл register.go)

package auth

import "context"

// RegisterInput — данные для регистрации.
type RegisterInput struct {
	TenantID string
	Username string
	Email    string
	Password string
	UserData map[string]interface{}
}

// Register создаёт нового пользователя.
func (s *AuthService) Register(ctx context.Context, input RegisterInput) (*Tokens, error) {
	// ... реализация из предыдущего кода
}
