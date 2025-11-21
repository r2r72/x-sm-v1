-- 003_create_auth_schema.sql
-- Создаёт схему auth для multi-tenant ESM
-- Идемпотентно: можно запускать повторно

BEGIN;

-- Проверяем, не создана ли уже схема
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth') THEN
        CREATE SCHEMA auth;
    END IF;
END $$;

-- Таблица пользователей
CREATE TABLE IF NOT EXISTS auth.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT,
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    CONSTRAINT users_tenant_username_key UNIQUE (tenant_id, username),
    CONSTRAINT users_tenant_email_key UNIQUE (tenant_id, email)
);

-- Индексы
CREATE INDEX IF NOT EXISTS idx_users_tenant_username 
ON auth.users (tenant_id, username) WHERE active = true;

-- RLS
ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;

-- Политика (только если не существует)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE schemaname = 'auth' AND tablename = 'users' AND policyname = 'tenant_isolation_users'
    ) THEN
        CREATE POLICY tenant_isolation_users ON auth.users
        USING (tenant_id = current_setting('app.current_tenant', true)::UUID);
    END IF;
END $$;

COMMIT;