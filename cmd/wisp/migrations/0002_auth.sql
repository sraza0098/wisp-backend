-- 0002_auth.sql — normalize users table to match API:
-- final shape: users(id UUID PK, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)

-- 1) Ensure columns exist
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS username TEXT,
  ADD COLUMN IF NOT EXISTS password_hash TEXT;

-- 2) If legacy 'handle' exists, copy it into username where username is NULL
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='users' AND column_name='handle'
  ) THEN
    UPDATE users
      SET username = handle
      WHERE username IS NULL;
  END IF;
END $$;

-- 3) Drop legacy unique constraint on 'handle' if present
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='users_handle_key'
  ) THEN
    ALTER TABLE users DROP CONSTRAINT users_handle_key;
  END IF;
END $$;

-- 4) Drop legacy 'handle' column if present
ALTER TABLE users DROP COLUMN IF EXISTS handle;

-- 5) Enforce NOT NULL invariants
ALTER TABLE users
  ALTER COLUMN username SET NOT NULL,
  ALTER COLUMN password_hash SET NOT NULL;

-- 6) Ensure uniqueness on username (idempotent)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname='public' AND indexname='users_username_key'
  ) THEN
    CREATE UNIQUE INDEX users_username_key ON users(username);
  END IF;
END $$;
