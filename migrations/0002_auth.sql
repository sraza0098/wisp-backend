-- Add username & password_hash to existing users table (safe/idempotent)
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS username TEXT,
  ADD COLUMN IF NOT EXISTS password_hash TEXT;

-- If you previously stored "handle", default username to handle where missing
UPDATE users
SET username = COALESCE(username, handle)
WHERE username IS NULL;

-- Add uniqueness on username if not already present
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'users_username_key'
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_username_key UNIQUE (username);
  END IF;
END $$;

-- NOTE: We avoid NOT NULL here to keep migration safe if rows exist without values.
-- App enforces non-empty username/password on insert.
