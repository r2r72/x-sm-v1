// internal/repository/pg/auth.go
package pg

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	auth "github.com/r2r72/x-sm-v1/internal/service/auth"
)

type AuthRepository struct {
	db *pgxpool.Pool
}

func NewAuthRepository(db *pgxpool.Pool) *AuthRepository {
	return &AuthRepository{db: db}
}

func (r *AuthRepository) CreateUser(ctx context.Context, u *auth.User) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO auth.users (id, tenant_id, username, email, password_hash, mfa_enabled, active)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		u.ID, u.TenantID, u.Username, u.Email, u.PasswordHash, u.MFAEnabled, u.Active,
	)
	return err
}

func (r *AuthRepository) GetUserByUsername(ctx context.Context, tenantID, username string) (*auth.User, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, tenant_id, username, email, password_hash, mfa_enabled, active
		 FROM auth.users
		 WHERE tenant_id = $1 AND username = $2 AND active = true`,
		tenantID, username)

	var u auth.User
	err := row.Scan(
		&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash,
		&u.MFAEnabled, &u.Active,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, auth.ErrInvalidCredentials
		}
		return nil, err
	}
	return &u, nil
}

func (r *AuthRepository) CreateSession(ctx context.Context, s *auth.Session) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO auth.sessions (id, user_id, tenant_id, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		s.ID, s.UserID, s.TenantID, s.ExpiresAt,
	)
	return err
}

func (r *AuthRepository) GetSession(ctx context.Context, sessionID string) (*auth.Session, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, user_id, tenant_id, expires_at
		 FROM auth.sessions
		 WHERE id = $1 AND expires_at > NOW()`,
		sessionID)

	var s auth.Session
	err := row.Scan(&s.ID, &s.UserID, &s.TenantID, &s.ExpiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, auth.ErrSessionExpired
		}
		return nil, err
	}
	return &s, nil
}

func (r *AuthRepository) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := r.db.Exec(ctx, "DELETE FROM auth.sessions WHERE id = $1", sessionID)
	return err
}

func (r *AuthRepository) DeleteSessionsByUser(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx, "DELETE FROM auth.sessions WHERE user_id = $1", userID)
	return err
}

func (r *AuthRepository) LogLoginAttempt(ctx context.Context, a *auth.LoginAttempt) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO auth.login_attempts (tenant_id, username, ip_address, success, failure_reason, created_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())`,
		a.TenantID, a.Username, a.IP, a.Success, a.Reason,
	)
	return err
}
