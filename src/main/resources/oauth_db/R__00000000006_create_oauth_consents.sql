CREATE TABLE oauth_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255),
    client_id UUID NOT NULL,
    scopes TEXT NOT NULL,
    granted_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE (user_id, client_id)
);

CREATE INDEX idx_oauth_consents_user_client ON oauth_consents (user_id, client_id);
