// Package auth defines domain types for authentication.
package auth

import "time"

// User represents a user in the auth layer.
type User struct {
	ID           string
	TenantID     string
	Username     string
	Email        string
	PasswordHash string
	MFAEnabled   bool
	MFASecret    string // base32, decrypted
	Active       bool
}

// Session represents a temporary MFA session.
type Session struct {
	ID        string
	UserID    string
	TenantID  string
	MFASecret string
	ExpiresAt time.Time
}

// LoginAttempt is for audit logging.
type LoginAttempt struct {
	TenantID  string
	Username  string
	IP        string
	UserAgent string
	Success   bool
	Reason    string
}

// Tokens holds JWT tokens.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	UserID       string
}

// RegisterInput is the input for user registration.
type RegisterInput struct {
	TenantID string
	Username string
	Email    string
	Password string
	UserData map[string]interface{}
}

// LoginInput is the input for login.
type LoginInput struct {
	TenantID  string
	Username  string
	Password  string
	IPAddress string
	UserAgent string
}

// LoginResult is the result of a login attempt.
type LoginResult struct {
	Tokens      *Tokens
	SessionID   string
	RequiresMFA bool
}
