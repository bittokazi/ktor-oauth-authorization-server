CREATE TABLE IF NOT EXISTS trusted_devices (
  id SERIAL NOT NULL,
  user_id varchar(255) NOT NULL,
  device_ip varchar(255) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
