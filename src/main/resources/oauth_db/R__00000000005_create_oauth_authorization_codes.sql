CREATE TABLE oauth_authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL REFERENCES oauth_users (id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_oauth_auth_codes_client_id ON oauth_authorization_codes (client_id);
CREATE INDEX idx_oauth_auth_codes_user_id ON oauth_authorization_codes (user_id);
CREATE INDEX idx_oauth_auth_codes_expires_at ON oauth_authorization_codes (expires_at);
