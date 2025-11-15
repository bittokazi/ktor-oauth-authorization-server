CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    client_type VARCHAR(50) NOT NULL CHECK (client_type IN ('confidential', 'public')),
    redirect_uris TEXT NOT NULL,
    scopes TEXT,
    grant_types TEXT,
    token_endpoint_auth_method VARCHAR(100) DEFAULT 'client_secret_basic',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    access_token_validity BIGINT NOT NULL,
    refresh_token_validity BIGINT NOT NULL
);

CREATE INDEX idx_oauth_clients_client_id ON oauth_clients (client_id);
