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

	// --- App ---
	app := fiber.New()

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
	return c.SendStatus(http.StatusCreated)
	})

	// List messages in a room
	protected.Get("/rooms/:roomId/messages", func(c *fiber.Ctx) error {
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

	afterStr := c.Query("after", "")
	limit := 50
	if v := c.Query("limit", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 { limit = n }
	}

	var rows *sql.Rows; var qerr error
	if afterStr != "" {
		t, err := time.Parse(time.RFC3339, afterStr)
		if err != nil { return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error":"bad after (RFC3339)"}) }
		rows, qerr = db.QueryContext(c.Context(),
			`SELECT m.id, m.room_id, m.sender_id, u.username, m.kind, m.body, m.created_at
			FROM messages m JOIN users u ON u.id = m.sender_id
			WHERE m.room_id=$1 AND m.created_at > $2
			ORDER BY m.created_at DESC LIMIT $3`, roomID, t, limit)
	} else {
		rows, qerr = db.QueryContext(c.Context(),
			`SELECT m.id, m.room_id, m.sender_id, u.username, m.kind, m.body, m.created_at
			FROM messages m JOIN users u ON u.id = m.sender_id
			WHERE m.room_id=$1
			ORDER BY m.created_at DESC LIMIT $2`, roomID, limit)
	}
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
