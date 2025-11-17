CREATE TABLE IF NOT EXISTS users (
  id SERIAL NOT NULL,
  email varchar(255) NOT NULL,
  first_name varchar(255) NOT NULL,
  last_name varchar(255) NOT NULL,
  password varchar(255) NOT NULL,
  two_fa_enabled BOOLEAN DEFAULT FALSE,
  two_fa_secret varchar(255) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT user_name_key UNIQUE (email)
);

-- Insert a default test user
INSERT INTO users (id, password, email, first_name, last_name, created_at, two_fa_enabled, two_fa_secret)
VALUES (
    1,
    -- bcrypt hash for password: "password"
    '$2a$10$x3Tf4hmeDfHBA3R.5rCf9u6BAKGdr5vlE8zRdCDAEEr6bjCCsPnAW',
    'admin@example.com',
    'Jon',
    'Doe',
    now(),
    FALSE,
    ''
)
ON CONFLICT (email) DO NOTHING;
