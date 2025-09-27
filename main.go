package main

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
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
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		env("DB_USER", "wisp"),
		env("DB_PASSWORD", "wisp123"),
		env("DB_HOST", "postgres-postgresql.postgres.svc.cluster.local"),
		env("DB_PORT", "5432"),
		env("DB_NAME", "wispdb"),
	)

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

	app := fiber.New()

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Wisp backend is up ✅\nTry /health, /time, /version, /v1/rooms")
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

	// --- Minimal API for Day 4 ---

	// Create a room
	app.Post("/v1/rooms", func(c *fiber.Ctx) error {
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

	// List rooms
	app.Get("/v1/rooms", func(c *fiber.Ctx) error {
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

	log.Fatal(app.Listen(":8080"))
}
