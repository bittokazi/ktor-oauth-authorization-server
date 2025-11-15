-- Ensure only one default client can exist
CREATE UNIQUE INDEX unique_default_client_idx
ON oauth_clients ((is_default))
WHERE is_default = TRUE;
