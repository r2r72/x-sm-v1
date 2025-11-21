// Package auth defines authentication errors.
package auth

import "errors"

var (
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserInactive       = errors.New("user is inactive")
	ErrInvalidPassword    = errors.New("password does not meet policy")
	ErrInvalidMFA         = errors.New("invalid mfa code")
	ErrSessionExpired     = errors.New("mfa session expired")
	ErrInvalidToken       = errors.New("invalid refresh token")
)
