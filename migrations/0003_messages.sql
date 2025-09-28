CREATE TABLE IF NOT EXISTS room_members (
    room_id   UUID NOT NULL,
    user_id   UUID NOT NULL,
    role      TEXT NOT NULL DEFAULT 'member',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (room_id, user_id),
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id);

CREATE TABLE IF NOT EXISTS messages (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id    UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    sender_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL DEFAULT 'text',
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'messages' AND column_name = 'created_at'
  ) THEN
    ALTER TABLE messages ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'messages' AND column_name = 'ts'
  ) THEN
    UPDATE messages SET created_at = ts WHERE created_at IS NULL OR created_at = now();
    -- optional: DROP COLUMN ts after backfill
    -- ALTER TABLE messages DROP COLUMN ts;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_messages_room_created_at
  ON messages(room_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_sender_created_at
  ON messages(sender_id, created_at DESC);
