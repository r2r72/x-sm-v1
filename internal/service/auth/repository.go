// Package auth defines the repository contract for authentication.
package auth

import "context"

// AuthRepository is the interface for DB operations.
// Must be implemented by pg.AuthRepository.
type AuthRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, tenantID, username string) (*User, error)
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteSessionsByUser(ctx context.Context, userID string) error
	LogLoginAttempt(ctx context.Context, attempt *LoginAttempt) error
}
