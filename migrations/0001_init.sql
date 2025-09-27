create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  handle text unique not null,
  created_at timestamptz not null default now()
);

create table if not exists rooms (
  id uuid primary key default gen_random_uuid(),
  type text not null check (type in ('dm','group','geo')),
  title text,
  created_at timestamptz not null default now()
);

create table if not exists room_members (
  room_id uuid not null references rooms(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  primary key (room_id, user_id)
);

create table if not exists messages (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references rooms(id) on delete cascade,
  sender_id uuid not null references users(id),
  ts timestamptz not null default now(),
  kind text not null check (kind in ('text','media','ptt')),
  body text,
  lang text
);
