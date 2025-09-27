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
	// pgcrypto gives us gen_random_uuid()
	if _, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto;`); err != nil {
		return fmt.Errorf("enable pgcrypto: %w", err)
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	for _, e := range entries {
		sqlb, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		if _, err := db.ExecContext(ctx, string(sqlb)); err != nil {
			return fmt.Errorf("apply %s: %w", e.Name(), err)
		}
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
			`INSERT INTO users (username, password_hash) VALUES ($1, $2)`, req.Username, string(hash))
		if err != nil {
			// unique violation or other error
			return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "username exists or db error"})
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
			SigningKey:   jwtSecret,
			ContextKey:   "jwt", // c.Locals("jwt")
			ErrorHandler: func(c *fiber.Ctx, err error) error { return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"}) },
		}),
	)

	// Create room (protected)
	protected.Post("/rooms", func(c *fiber.Ctx) error {
		var req struct {
			Title string `json:"title"`
			Type  string `json:"type"` // dm | group | geo
		}
		if err := c.BodyParser(&req); err != nil || req.Type == "" {
			return c.Status(http.StatusBadRequest).SendString("bad json")
		}
		if req.Title == "" {
			req.Title = req.Type
		}
		_, err := db.ExecContext(c.Context(),
			`INSERT INTO rooms(type, title) VALUES ($1, $2)`, req.Type, req.Title)
		if err != nil {
			return c.Status(http.StatusInternalServerError).SendString("db error")
		}
		return c.SendStatus(http.StatusCreated)
	})

	// List rooms (protected)
	protected.Get("/rooms", func(c *fiber.Ctx) error {
		rows, err := db.QueryContext(c.Context(),
			`SELECT id, type, title, created_at FROM rooms ORDER BY created_at DESC LIMIT 50`)
		if err != nil {
			return c.Status(http.StatusInternalServerError).SendString("db error")
		}
		defer rows.Close()
		type room struct {
			ID        string    `json:"id"`
			Type      string    `json:"type"`
			Title     string    `json:"title"`
			CreatedAt time.Time `json:"createdAt"`
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

	// Route dump for debugging
	go func() {
		time.Sleep(200 * time.Millisecond)
		routes := app.GetRoutes()
		b, _ := json.MarshalIndent(routes, "", "  ")
		log.Printf("ROUTES:\n%s\n", string(b))
	}()
	app.Get("/__routes", func(c *fiber.Ctx) error { return c.JSON(app.GetRoutes()) })

	// Serve
	log.Fatal(app.Listen(":" + env("PORT", "8080")))
}
