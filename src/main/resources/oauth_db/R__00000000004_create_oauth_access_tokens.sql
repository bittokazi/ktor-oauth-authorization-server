CREATE TABLE oauth_access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token TEXT NOT NULL UNIQUE,
    client_id UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id VARCHAR(255) REFERENCES oauth_users (id) ON DELETE CASCADE,
    scopes TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    issued_at TIMESTAMPTZ DEFAULT now(),
    refresh_token_id UUID REFERENCES oauth_refresh_tokens (id)
);

CREATE INDEX idx_oauth_access_tokens_client_id ON oauth_access_tokens (client_id);
CREATE INDEX idx_oauth_access_tokens_user_id ON oauth_access_tokens (user_id);
CREATE INDEX idx_oauth_access_tokens_expires_at ON oauth_access_tokens (expires_at);
