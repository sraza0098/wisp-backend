```markdown
# Wisp Backend

A lightweight chat backend written in Go using [Fiber](https://gofiber.io).  
It provides:

- User signup/login with JWT auth
- Room management (create, list, join)
- Messaging (send, list, read receipts)
- Presence tracking (who is online, last seen)
- Typing indicators
- WebSocket support for real-time events
- PostgreSQL for storage
- Redis for presence state

---

## 🏗 Project Layout

```

wisp-backend/
cmd/wisp/             # main app entrypoint
main.go             # bootstrap & wiring
config.go           # env vars
migrations.go       # DB migrations runner
ws_hub.go           # WebSocket hub (broadcasts)
presence.go         # Redis-based presence
typing.go           # typing state
routes_base.go      # health/version/base routes
routes_auth.go      # signup/login + JWT
routes_rooms.go     # create/list/join rooms
routes_messages.go  # messages + reads
routes_presence.go  # presence + typing endpoints
ws.go               # WebSocket handler
migrations/           # SQL migration files
Dockerfile
Makefile
go.mod / go.sum

````

---

## ⚡ Quick Start (Local)

### Requirements

- Go ≥ 1.23 (or `golang:1.25` if using Docker image)
- PostgreSQL
- Redis

### Environment

Set these variables (defaults are provided):

```bash
export PORT=8081
export JWT_SECRET=dev-secret-please-change

export DB_HOST=
export DB_PORT=
export DB_USER=wisp
export DB_PASSWORD=
export DB_NAME=

export REDIS_ADDR=127.0.0.1:6379
export REDIS_PASSWORD=
````

### Run

```bash
make run
```

Server will start on `http://127.0.0.1:8081`.

---

## 🗄 Database Migrations

Migrations live in `migrations/*.sql` and are auto-applied on startup
(using Go’s `embed`).

---

## 🧪 Example API Flow

1. **Sign up**

```bash
curl -X POST http://127.0.0.1:8081/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret"}'
```

2. **Login**

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8081/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret"}' | jq -r .token)
```

3. **Create Room**

```bash
curl -X POST http://127.0.0.1:8081/v1/rooms \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"General","type":"group"}'
```

4. **Open WebSocket**

```bash
wscat -c "ws://127.0.0.1:8081/ws?roomId=<roomId>&token=$TOKEN"
```

---

## 🐳 Docker

Build image:

```bash
make docker TAG=dev
```

Run container:

```bash
docker run --rm -p 8081:8081 \
  -e PORT=8081 \
  -e DB_HOST=host.docker.internal -e DB_USER=wisp -e DB_PASSWORD=wisp123 -e DB_NAME=wispdb \
  -e REDIS_ADDR=host.docker.internal:6379 \
  -e JWT_SECRET=dev-secret-please-change \
  ghcr.io/sraza0098/wisp-backend:dev
```

Multi-arch release:

```bash
make release TAG=0.1.0
```

---

## 🔍 Useful Commands

* Run tests:

  ```bash
  make test
  ```

* Print routes (after server is running):

  ```bash
  make routes
  ```

* Clean binaries:

  ```bash
  make clean
  ```

---

## 📜 License

MIT (or your chosen license)

```

---

```
