-- Insert a default test user
INSERT INTO oauth_users (id, username, password_hash, email, first_name, last_name, is_active, created_at)
VALUES (
    gen_random_uuid(),
    'admin',
    -- bcrypt hash for password: "password"
    '$2a$10$x3Tf4hmeDfHBA3R.5rCf9u6BAKGdr5vlE8zRdCDAEEr6bjCCsPnAW',
    'admin@example.com',
    'Jon',
    'Doe',
    TRUE,
    now()
)
ON CONFLICT (username) DO NOTHING;

-- Insert a default test OAuth client
INSERT INTO oauth_clients (
    id,
    client_id,
    client_secret,
    client_name,
    client_type,
    redirect_uris,
    scopes,
    grant_types,
    token_endpoint_auth_method,
    created_at,
    access_token_validity,
    refresh_token_validity,
    is_default,
    consent_required
)
VALUES (
    gen_random_uuid(),
    'default-client',
    'password',
    'Default Application',
    'confidential',
    '',
    'openid,profile,email',
    'authorization_code,refresh_token,client_credentials',
    'client_secret_post',
    now(),
    300,
    7200,
    TRUE,
    TRUE
)
ON CONFLICT (client_id) DO NOTHING;
