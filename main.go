package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"strconv"
    "strings"
	"sort"
	"errors"
	"sync"

	"github.com/redis/go-redis/v9"
	"github.com/gofiber/contrib/websocket"
  	"github.com/jackc/pgx/v5/pgconn"
	"github.com/gofiber/fiber/v2"
	jwtware "github.com/gofiber/jwt/v3"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

func env(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func runMigrations(ctx context.Context, db *sql.DB) error {
    if _, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto;`); err != nil {
        return fmt.Errorf("enable pgcrypto: %w", err)
    }
    entries, err := migrationFS.ReadDir("migrations")
    if err != nil {
        return fmt.Errorf("read migrations: %w", err)
    }

    // 🔑 sort so 0001, 0002, 0003 apply in order
    sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

    for _, e := range entries {
        sqlb, err := migrationFS.ReadFile("migrations/" + e.Name())
        if err != nil {
            return fmt.Errorf("read %s: %w", e.Name(), err)
        }
        if _, err := db.ExecContext(ctx, string(sqlb)); err != nil {
            return fmt.Errorf("migrate:apply %s: %w", e.Name(), err)
        }
		log.Println(" -", e.Name())
    }
    return nil
}

type wsClient struct {
    conn *websocket.Conn
    send chan []byte
    user string
}

type wsHub struct {
    mu    sync.RWMutex
    rooms map[string]map[*wsClient]struct{}
}
type typingState struct {
    mu    sync.Mutex
    byRoom map[string]map[string]time.Time // roomID -> username -> expiresAt
}
var typing = typingState{byRoom: map[string]map[string]time.Time{}}

func newHub() *wsHub {
    return &wsHub{rooms: make(map[string]map[*wsClient]struct{})}
}
func (h *wsHub) add(room string, c *wsClient) {
    h.mu.Lock(); defer h.mu.Unlock()
    if h.rooms[room] == nil { h.rooms[room] = make(map[*wsClient]struct{}) }
    h.rooms[room][c] = struct{}{}
}
func (h *wsHub) remove(room string, c *wsClient) {
    h.mu.Lock(); defer h.mu.Unlock()
    if m, ok := h.rooms[room]; ok {
        delete(m, c)
        if len(m) == 0 { delete(h.rooms, room) }
    }
}
func (h *wsHub) broadcast(room string, payload []byte) {
    h.mu.RLock(); defer h.mu.RUnlock()
    for c := range h.rooms[room] {
        select { case c.send <- payload: default: /* drop if slow */ }
    }
}


type Presence struct {
	rdb      *redis.Client
	ttl      time.Duration
	tick     time.Duration
  }
  
  func NewPresence(r *redis.Client, ttl, tick time.Duration) *Presence {
	return &Presence{rdb: r, ttl: ttl, tick: tick}
  }
  
  // keys:
  //   pres:user:{userId} = "1" (EX ttl)
  //   pres:room:{roomId} = Set of userIds (no TTL, cleaned on fetch)
  //   lastseen:{userId}   = timestamp (string RFC3339) for quick peek (optional)
  func (p *Presence) heartbeatUser(ctx context.Context, userId string) error {
	return p.rdb.Set(ctx, "pres:user:"+userId, "1", p.ttl).Err()
  }
  func (p *Presence) addToRoom(ctx context.Context, roomId, userId string) error {
	return p.rdb.SAdd(ctx, "pres:room:"+roomId, userId).Err()
  }
  func (p *Presence) removeFromRoom(ctx context.Context, roomId, userId string) error {
	return p.rdb.SRem(ctx, "pres:room:"+roomId, userId).Err()
  }
  func (p *Presence) onlineInRoom(ctx context.Context, roomId string) ([]string, error) {
	users, err := p.rdb.SMembers(ctx, "pres:room:"+roomId).Result()
	if err != nil { return nil, err }
	out := make([]string, 0, len(users))
	for _, u := range users {
	  exists, _ := p.rdb.Exists(ctx, "pres:user:"+u).Result()
	  if exists == 1 {
		out = append(out, u)
	  } else {
		// cleanup stale
		_ = p.rdb.SRem(ctx, "pres:room:"+roomId, u).Err()
	  }
	}
	return out, nil
  }
  func (p *Presence) setLastSeen(ctx context.Context, userId string, t time.Time) {
	_ = p.rdb.Set(ctx, "lastseen:"+userId, t.Format(time.RFC3339), 0).Err()
  }

  
func main() {
	// --- Config ---
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		env("DB_USER", "wisp"),
		env("DB_PASSWORD", "wisp123"),
		env("DB_HOST", "postgres-postgresql.postgres.svc.cluster.local"),
		env("DB_PORT", "5432"),
		env("DB_NAME", "wispdb"),
	)
	jwtSecret := []byte(env("JWT_SECRET", "dev-secret-please-change"))

	// --- DB + migrations ---
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal("sql.Open:", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatal("db ping:", err)
	}
	if err := runMigrations(ctx, db); err != nil {
		log.Fatal("migrate:", err)
	}

	// --- Redis + Presence ---
	rdb := redis.NewClient(&redis.Options{
		Addr:     env("REDIS_ADDR", "127.0.0.1:6379"),
		Password: env("REDIS_PASSWORD", ""),
		DB:       0,
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatal("redis ping:", err)
	}
	pres := NewPresence(
		rdb,
		time.Duration(func() int { if v, _ := strconv.Atoi(env("PRESENCE_TTL_SECONDS","60")); v>0 {return v}; return 60 }())*time.Second,
		time.Duration(func() int { if v, _ := strconv.Atoi(env("PRESENCE_TICK_SECONDS","20")); v>0 {return v}; return 20 }())*time.Second,
	)


	// --- App + hub ---
	app := fiber.New()
	hub := newHub()

	// Basic endpoints
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Wisp backend ✅  Try: /health, /time, /version, /v1/users, /v1/login, /v1/rooms")
	})
	app.Get("/health", func(c *fiber.Ctx) error {
		if err := db.Ping(); err != nil {
			return c.Status(http.StatusServiceUnavailable).SendString("db: down")
		}
		return c.SendString("ok")
	})
	app.Get("/time", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"utc": time.Now().UTC()})
	})
	app.Get("/version", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"version": os.Getenv("WISP_VERSION")})
	})

	// --- Auth: signup/login ---

	type userRow struct {
		ID           string
		Username     string
		PasswordHash string
	}

	// POST /v1/users  {username,password}
	app.Post("/v1/users", func(c *fiber.Ctx) error {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&req); err != nil || req.Username == "" || req.Password == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "username & password required"})
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "hash error"})
		}
		// insert (username unique)
		_, err = db.ExecContext(c.Context(),
			`INSERT INTO users (username, password_hash) VALUES ($1, $2)`,
			req.Username, string(hash),
		)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error":"username exists"})
			}
			log.Printf("signup db error: %v", err) // <-- keep this while debugging
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error":"db error"})
		}
		return c.SendStatus(http.StatusCreated)
	})

	// POST /v1/login  {username,password} -> {token}
	app.Post("/v1/login", func(c *fiber.Ctx) error {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&req); err != nil || req.Username == "" || req.Password == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "username & password required"})
		}

		var u userRow
		err := db.QueryRowContext(c.Context(),
			`SELECT id, username, password_hash FROM users WHERE username=$1`, req.Username).
			Scan(&u.ID, &u.Username, &u.PasswordHash)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}

		// issue JWT
		claims := jwt.MapClaims{
			"sub": u.ID,
			"usr": u.Username,
			"exp": time.Now().Add(24 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(jwtSecret)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "token error"})
		}
		return c.JSON(fiber.Map{"token": signed})
	})

	// --- Protected API group (JWT required) ---
	protected := app.Group("/v1",
	jwtware.New(jwtware.Config{
		SigningKey: jwtSecret,
		ContextKey: "jwt",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		},
	}),
	)

	// helper: get user ID (sub) from JWT
	// helper: get user ID (sub) from Authorization header (version-agnostic)
	getUserID := func(c *fiber.Ctx) (string, error) {
		auth := c.Get("Authorization")
		if auth == "" {
			// Some clients send lowercase; headers are case-insensitive, but just in case:
			auth = c.Get("authorization")
		}
		const p = "Bearer "
		if !strings.HasPrefix(auth, p) {
			return "", fmt.Errorf("no bearer")
		}
		tokenStr := strings.TrimSpace(auth[len(p):])

		// Parse & validate using our HS256 secret
		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("unexpected alg")
			}
			return []byte(env("JWT_SECRET", "dev-secret-please-change")), nil
		})
		if err != nil || !tok.Valid {
			return "", fmt.Errorf("invalid token")
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			return "", fmt.Errorf("bad claims")
		}
		sub, _ := claims["sub"].(string)
		if sub == "" {
			return "", fmt.Errorf("no sub")
		}
		return sub, nil
	}


	// --- Day 6 routes (MUST be before Listen) ---

	// Create room
	protected.Post("/rooms", func(c *fiber.Ctx) error {
	var req struct {
		Title string `json:"title"`
		Type  string `json:"type"` // dm | group | geo
	}
	if err := c.BodyParser(&req); err != nil || req.Type == "" {
		return c.Status(http.StatusBadRequest).SendString("bad json")
	}
	if req.Title == "" { req.Title = req.Type }
	if _, err := db.ExecContext(c.Context(),
		`INSERT INTO rooms(type, title) VALUES ($1,$2)`, req.Type, req.Title); err != nil {
		return c.Status(http.StatusInternalServerError).SendString("db error")
	}
	return c.SendStatus(http.StatusCreated)
	})

	// List rooms
	protected.Get("/rooms", func(c *fiber.Ctx) error {
	rows, err := db.QueryContext(c.Context(),
		`SELECT id, type, title, created_at FROM rooms ORDER BY created_at DESC LIMIT 50`)
	if err != nil { return c.Status(http.StatusInternalServerError).SendString("db error") }
	defer rows.Close()
	type room struct {
		ID string `json:"id"`; Type string `json:"type"`; Title string `json:"title"`; CreatedAt time.Time `json:"createdAt"`
	}
	var out []room
	for rows.Next() {
		var r room
		if err := rows.Scan(&r.ID, &r.Type, &r.Title, &r.CreatedAt); err != nil {
			return c.Status(http.StatusInternalServerError).SendString("scan error")
		}
		out = append(out, r)
	}
	return c.JSON(out)
	})

	// Join room (idempotent)
	protected.Post("/rooms/:roomId/join", func(c *fiber.Ctx) error {
	userID, err := getUserID(c)
	if err != nil { return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error":"unauthorized"}) }
	roomID := c.Params("roomId")
	if roomID == "" { return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error":"missing roomId"}) }

	var exists bool
	if err := db.QueryRowContext(c.Context(),
		`SELECT EXISTS (SELECT 1 FROM rooms WHERE id=$1)`, roomID).Scan(&exists); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":"db error"})
	}
	if !exists { return c.Status(http.StatusNotFound).JSON(fiber.Map{"error":"room not found"}) }

	if _, err := db.ExecContext(c.Context(),
		`INSERT INTO room_members(room_id,user_id) VALUES ($1,$2)
		ON CONFLICT (room_id,user_id) DO NOTHING`, roomID, userID); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":"db error"})
	}
	return c.SendStatus(http.StatusNoContent)
	})

	protected.Post("/rooms/:roomId/typing", func(c *fiber.Ctx) error {
		userID, err := getUserID(c); if err != nil { return c.SendStatus(401) }
	
		// look up username for display (optional but nicer)
		var username string
		_ = db.QueryRowContext(c.Context(),
			`SELECT username FROM users WHERE id=$1`, userID).Scan(&username)
		if username == "" { username = userID } // fallback
	
		roomID := c.Params("roomId")
		if roomID == "" { return c.SendStatus(400) }
	
		typing.mu.Lock()
		if typing.byRoom[roomID] == nil { typing.byRoom[roomID] = map[string]time.Time{} }
		typing.byRoom[roomID][username] = time.Now().Add(3 * time.Second) // expires in 3s
		typing.mu.Unlock()
	
		// (optional) also broadcast to WS listeners
		// payload, _ := json.Marshal(fiber.Map{"type":"typing","roomId":roomID,"user":username,"ts":time.Now().UTC()})
		// hub.broadcast(roomID, payload)
	
		return c.SendStatus(204)
	})
	
	protected.Get("/rooms/:roomId/typing", func(c *fiber.Ctx) error {
		roomID := c.Params("roomId")
		if roomID == "" { return c.SendStatus(400) }
	
		now := time.Now()
		typing.mu.Lock()
		m := typing.byRoom[roomID]
		out := []string{}
		for u, exp := range m {
			if now.Before(exp) { out = append(out, u) } else { delete(m, u) }
		}
		typing.mu.Unlock()
	
		return c.JSON(out)
	})
	
	// Send message
	protected.Post("/rooms/:roomId/messages", func(c *fiber.Ctx) error {
	userID, err := getUserID(c)
	if err != nil { return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error":"unauthorized"}) }
	roomID := c.Params("roomId")
	if roomID == "" { return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error":"missing roomId"}) }

	var member bool
	if err := db.QueryRowContext(c.Context(),
		`SELECT EXISTS (SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2)`,
		roomID, userID).Scan(&member); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":"db error"})
	}
	if !member { return c.Status(http.StatusForbidden).JSON(fiber.Map{"error":"join room first"}) }

	var req struct{ Body, Kind string }
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Body) == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error":"body required"})
	}
	if req.Kind == "" { req.Kind = "text" }

	if _, err := db.ExecContext(c.Context(),
		`INSERT INTO messages(room_id, sender_id, kind, body) VALUES ($1,$2,$3,$4)`,
		roomID, userID, req.Kind, req.Body); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":"db error"})
	}
	payload, _ := json.Marshal(fiber.Map{
		"type": "message",
		"roomId": roomID,
		"from":  userID,
		"kind":  req.Kind,
		"body":  req.Body,
		"ts":    time.Now().UTC(),
	})
	hub.broadcast(roomID, payload)
	
	return c.SendStatus(http.StatusCreated)
	})

	// List messages in a room
	protected.Get("/rooms/:roomId/messages", func(c *fiber.Ctx) error {
		userID, err := getUserID(c); if err != nil { return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error":"unauthorized"}) }
		roomID := c.Params("roomId"); if roomID == "" { return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error":"missing roomId"}) }

		var member bool
		if err := db.QueryRowContext(c.Context(),
			`SELECT EXISTS (SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2)`,
			roomID, userID).Scan(&member); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":"db error"})
		}
		if !member { return c.Status(http.StatusForbidden).JSON(fiber.Map{"error":"join room first"}) }

		limit := 50
		if v := c.Query("limit", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 { limit = n }
		}
		beforeStr := c.Query("before", "")

		var rows *sql.Rows; var qerr error
		if beforeStr != "" {
			t, err := time.Parse(time.RFC3339, beforeStr)
			if err != nil { return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error":"bad before (RFC3339)"}) }
			rows, qerr = db.QueryContext(c.Context(),
				`SELECT m.id, m.room_id, m.sender_id, u.username, m.kind, m.body, m.created_at
				   FROM messages m JOIN users u ON u.id = m.sender_id
				  WHERE m.room_id=$1 AND m.created_at < $2
				  ORDER BY m.created_at DESC, m.id DESC LIMIT $3`, roomID, t, limit+1)
		} else {
			rows, qerr = db.QueryContext(c.Context(),
				`SELECT m.id, m.room_id, m.sender_id, u.username, m.kind, m.body, m.created_at
				   FROM messages m JOIN users u ON u.id = m.sender_id
				  WHERE m.room_id=$1
				  ORDER BY m.created_at DESC, m.id DESC LIMIT $2`, roomID, limit+1)
		}
		if qerr != nil { return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":"db error"}) }
		defer rows.Close()

		type msg struct{ ID, RoomID, SenderID, Sender, Kind, Body string; CreatedAt time.Time }
		var items []msg
		for rows.Next() {
			var m msg
			if err := rows.Scan(&m.ID, &m.RoomID, &m.SenderID, &m.Sender, &m.Kind, &m.Body, &m.CreatedAt); err != nil {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":"scan error"})
			}
			items = append(items, m)
		}

		var nextCursor *string
		if len(items) > limit {
			items = items[:limit]
			nc := items[len(items)-1].CreatedAt.UTC().Format(time.RFC3339)
			nextCursor = &nc
		}
		return c.JSON(fiber.Map{"items": items, "nextCursor": nextCursor})
	})

	// GET /v1/rooms/:roomId/presence
	protected.Get("/rooms/:roomId/presence", func(c *fiber.Ctx) error {
		_, err := getUserID(c); if err != nil { return c.SendStatus(fiber.StatusUnauthorized) }
		roomID := c.Params("roomId")
		users, err := pres.onlineInRoom(c.Context(), roomID)
		if err != nil { return c.Status(500).JSON(fiber.Map{"error":"redis error"}) }
		return c.JSON(fiber.Map{"online": users})
	})

	// POST /v1/rooms/:roomId/read  { "messageId":"uuid" }
	protected.Post("/rooms/:roomId/read", func(c *fiber.Ctx) error {
		userID, err := getUserID(c); if err != nil { return c.SendStatus(fiber.StatusUnauthorized) }
		roomID := c.Params("roomId")
		var req struct{ MessageID string `json:"messageId"` }
		if err := c.BodyParser(&req); err != nil || req.MessageID == "" {
			return c.Status(400).JSON(fiber.Map{"error":"messageId required"})
		}
		_, err = db.ExecContext(c.Context(),
			`INSERT INTO message_reads(message_id, user_id, room_id)
			VALUES ($1,$2,$3)
			ON CONFLICT (message_id,user_id) DO UPDATE SET read_at = EXCLUDED.read_at`,
			req.MessageID, userID, roomID)
		if err != nil { return c.Status(500).JSON(fiber.Map{"error":"db error"}) }

		// Optional: if you have hub.broadcast from Day 7, emit a read event
		// payload, _ := json.Marshal(fiber.Map{
		//   "type":"read","roomId":roomID,"messageId":req.MessageID,"userId":userID,"at":time.Now().UTC(),
		// })
		// hub.broadcast(roomID, payload)

		return c.SendStatus(204)
	})

	// GET /v1/messages/:messageId/reads
	protected.Get("/messages/:messageId/reads", func(c *fiber.Ctx) error {
		_, err := getUserID(c); if err != nil { return c.SendStatus(fiber.StatusUnauthorized) }
		mid := c.Params("messageId")
		rows, qerr := db.QueryContext(c.Context(),
			`SELECT user_id, read_at FROM message_reads WHERE message_id=$1 ORDER BY read_at DESC`, mid)
		if qerr != nil { return c.Status(500).JSON(fiber.Map{"error":"db error"}) }
		defer rows.Close()
		type rr struct{ UserID string `json:"userId"`; ReadAt time.Time `json:"readAt"` }
		out := []rr{}
		for rows.Next() {
			var x rr
			if err := rows.Scan(&x.UserID, &x.ReadAt); err != nil {
				return c.Status(500).JSON(fiber.Map{"error":"scan"})
			}
			out = append(out, x)
		}
		return c.JSON(out)
	})

	// ---------- WebSocket endpoint: /ws?roomId=... ----------
	// Clients connect with a valid JWT in Sec-WebSocket-Protocol (subprotocol) as "Bearer <token>"
	app.Get("/ws", websocket.New(func(c *websocket.Conn) {
		// very small auth shim for dev: token in "Authorization" header or query
		roomID := c.Query("roomId")
		if roomID == "" { _ = c.Close(); return }

		tokenStr := c.Cookies("token")
		if tokenStr == "" {
			// try query param or header
			tokenStr = strings.TrimSpace(strings.TrimPrefix(c.Query("token"), "Bearer "))
			if tokenStr == "" {
				tokenStr = strings.TrimSpace(strings.TrimPrefix(c.Headers("Authorization"), "Bearer "))
			}
		}
		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !tok.Valid { _ = c.Close(); return }
		claims, ok := tok.Claims.(jwt.MapClaims); if !ok { _ = c.Close(); return }
		uid, _ := claims["sub"].(string); if uid == "" { _ = c.Close(); return }

		// --- PRESENCE: mark online + join room set ---
		// immediately mark user online and add to this room's online set
		_ = pres.heartbeatUser(context.Background(), uid)
		_ = pres.addToRoom(context.Background(), roomID, uid)

		// keep user online while socket is open (heartbeat every pres.tick)
		stop := make(chan struct{})
		go func() {
			t := time.NewTicker(pres.tick)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					_ = pres.heartbeatUser(context.Background(), uid)
				case <-stop:
					return
				}
			}
		}()
		// --------------------------------------------
		client := &wsClient{conn: c, send: make(chan []byte, 8), user: uid}
		hub.add(roomID, client)
		defer func() {
			// --- PRESENCE: cleanup on close ---
			close(stop)
			_ = pres.removeFromRoom(context.Background(), roomID, uid)
			pres.setLastSeen(context.Background(), uid, time.Now().UTC())
			// ----------------------------------
			hub.remove(roomID, client)
			close(client.send)
		}()

		// writer
		go func() {
			for msg := range client.send {
				if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			}
		}()

		// reader (ignore messages from client for now)
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))

	// Recent messages for the user
	protected.Get("/messages/recent", func(c *fiber.Ctx) error {
	userID, err := getUserID(c)
	if err != nil { return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error":"unauthorized"}) }
	limit := 50
	if v := c.Query("limit", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 { limit = n }
	}
	rows, qerr := db.QueryContext(c.Context(),
		`SELECT m.id, m.room_id, m.sender_id, u.username, m.kind, m.body, m.created_at
		FROM messages m
		JOIN room_members rm ON rm.room_id = m.room_id AND rm.user_id = $1
		JOIN users u ON u.id = m.sender_id
		ORDER BY m.created_at DESC LIMIT $2`, userID, limit)
	if qerr != nil { return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":"db error"}) }

	defer rows.Close()

	type msg struct {
		ID, RoomID, SenderID, Sender, Kind, Body string
		CreatedAt time.Time
	}
	var out []msg
	for rows.Next() {
		var m msg
		if err := rows.Scan(&m.ID, &m.RoomID, &m.SenderID, &m.Sender, &m.Kind, &m.Body, &m.CreatedAt); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":"scan error"})
		}
		out = append(out, m)
	}
	return c.JSON(out)
	})

	// route dump (dev)
	go func() {
	time.Sleep(200 * time.Millisecond)
	b, _ := json.MarshalIndent(app.GetRoutes(), "", "  ")
	log.Printf("ROUTES:\n%s\n", string(b))
	}()
	app.Get("/__routes", func(c *fiber.Ctx) error { return c.JSON(app.GetRoutes()) })

	// ---- LISTEN LAST ----
	log.Fatal(app.Listen(":" + env("PORT", "8080")))

}
