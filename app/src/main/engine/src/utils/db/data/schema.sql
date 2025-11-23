-- Essential Email/Password Authentication Schema
-- Version: 1.0

CREATE TABLE IF NOT EXISTS auth_users (
    uid TEXT PRIMARY KEY NOT NULL,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT,
    photo_url TEXT,
    phone_number TEXT,
    email_verified INTEGER DEFAULT 0,
    is_anonymous INTEGER DEFAULT 0,
    access_token TEXT,
    refresh_token TEXT,
    token_expiration INTEGER,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL,
    custom_claims TEXT
);


CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users (email);
CREATE INDEX IF NOT EXISTS idx_auth_users_token_expiration ON auth_users (token_expiration);
CREATE INDEX IF NOT EXISTS idx_auth_users_last_login ON auth_users (last_login_at);