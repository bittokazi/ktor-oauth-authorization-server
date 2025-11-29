CREATE TABLE oauth_device_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL,
    user_id VARCHAR(255),
    scopes TEXT NOT NULL,
    is_device_authorized BOOLEAN NOT NULL DEFAULT FALSE,
    device_code VARCHAR(128) NOT NULL,
    user_code VARCHAR(128) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now()
);
