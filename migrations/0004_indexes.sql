-- messages: fast timeline queries per room
CREATE INDEX IF NOT EXISTS idx_messages_room_created
  ON messages (room_id, created_at DESC, id DESC);

-- membership: fast “is member?” checks and joins
CREATE INDEX IF NOT EXISTS idx_room_members_user_room
  ON room_members (user_id, room_id);

-- rooms list ordering
CREATE INDEX IF NOT EXISTS idx_rooms_created
  ON rooms (created_at DESC);
