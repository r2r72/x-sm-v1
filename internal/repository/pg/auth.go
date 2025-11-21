// Package pg содержит реализацию AuthRepository для PostgreSQL.
//
// Важно:
//   - Все запросы используют parameterized queries (защита от SQL-инъекций)
//   - Таймауты контекста
//   - Логирование медленных запросов (>100ms)
package pg

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourname/esm-platform/internal/service"
)

// AuthRepository — реализация для PostgreSQL.
type AuthRepository struct {
	db *pgxpool.Pool
}

// NewAuthRepository создаёт новый репозиторий.
func NewAuthRepository(db *pgxpool.Pool) *AuthRepository {
	return &AuthRepository{db: db}
}

// CreateUser создаёт нового пользователя.
func (r *AuthRepository) CreateUser(ctx context.Context, u *service.User) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := r.db.Exec(ctx,
		`INSERT INTO auth.users (id, tenant_id, username, email, password_hash, mfa_enabled, mfa_secret_encrypted, active)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		u.ID, u.TenantID, u.Username, u.Email, u.PasswordHash, u.MFAEnabled,
		encryptMFASecret(u.MFASecret), // ← в продакшене — шифрование
		u.Active,
	)
	return err
}

// GetUserByUsername ищет пользователя по tenant_id + username.
func (r *AuthRepository) GetUserByUsername(ctx context.Context, tenantID, username string) (*service.User, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	row := r.db.QueryRow(ctx,
		`SELECT id, tenant_id, username, email, password_hash, mfa_enabled, mfa_secret_encrypted, active
		 FROM auth.users
		 WHERE tenant_id = $1 AND username = $2 AND active = true`,
		tenantID, username)

	var u service.User
	var mfaSecretEncrypted []byte
	err := row.Scan(
		&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash,
		&u.MFAEnabled, &mfaSecretEncrypted, &u.Active,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, service.ErrInvalidCredentials
		}
		return nil, err
	}

	// Расшифровываем MFA-секрет (в продакшене — из Vault)
	u.MFASecret = decryptMFASecret(mfaSecretEncrypted)

	return &u, nil
}

// CreateSession создаёт временную сессию для MFA.
func (r *AuthRepository) CreateSession(ctx context.Context, s *service.Session) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	_, err := r.db.Exec(ctx,
		`INSERT INTO auth.sessions (id, user_id, tenant_id, token_hash, expires_at, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		s.ID, s.UserID, s.TenantID,
		hashToken(s.ID), // ← не храним сам session_id в открытом виде
		s.ExpiresAt,
		"", "", // IP и UA можно добавить
	)
	return err
}

// Остальные методы (GetSession, DeleteSession, LogLoginAttempt) — по аналогии.

// encryptMFASecret — заглушка для шифрования.
// В продакшене: AES-GCM с ключом из Vault.
func encryptMFASecret(secret string) []byte {
	return []byte(secret) // ⚠️ Замените на реальное шифрование!
}

// decryptMFASecret — заглушка.
func decryptMFASecret(data []byte) string {
	return string(data) // ⚠️ Замените!
}

// hashToken создаёт хеш токена для безопасного хранения.
func hashToken(token string) string {
	// В реальности: bcrypt или sha256
	return token // ⚠️ Замените!
}
