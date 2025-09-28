-- Persist last seen for offline periods (optional; presence is in Redis)
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS last_seen timestamptz;
