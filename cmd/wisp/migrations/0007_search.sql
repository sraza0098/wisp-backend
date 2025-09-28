-- 0007_search.sql

-- Extensions for search
CREATE EXTENSION IF NOT EXISTS unaccent;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Add a plain column (not generated)
ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS tsv tsvector;

-- Trigger function to keep tsv in sync
CREATE OR REPLACE FUNCTION messages_tsv_update() RETURNS trigger AS $$
BEGIN
  NEW.tsv := to_tsvector('simple', unaccent(coalesce(NEW.body, '')));
  RETURN NEW;
END
$$ LANGUAGE plpgsql;

-- Trigger on INSERT/UPDATE of body
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_messages_tsv_update'
  ) THEN
    CREATE TRIGGER trg_messages_tsv_update
      BEFORE INSERT OR UPDATE OF body ON messages
      FOR EACH ROW EXECUTE FUNCTION messages_tsv_update();
  END IF;
END
$$;

-- Backfill existing rows
UPDATE messages
SET tsv = to_tsvector('simple', unaccent(coalesce(body, '')))
WHERE tsv IS NULL;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_messages_tsv_gin
  ON messages USING GIN (tsv);

CREATE INDEX IF NOT EXISTS idx_messages_body_trgm
  ON messages USING GIN (body gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_messages_room_created
  ON messages (room_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_sender_created
  ON messages (sender_id, created_at DESC);
