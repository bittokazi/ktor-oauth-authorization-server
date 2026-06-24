BEGIN;

-- Hash all existing client secrets with bcrypt
UPDATE oauth_clients
SET client_secret = crypt(client_secret, gen_salt('bf', 12));

COMMIT;
