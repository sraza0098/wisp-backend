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

func mustGetEnv(k, def string) string {
  v := os.Getenv(k)
  if v == "" { return def }
  return v
}

func runMigrations(ctx context.Context, db *sql.DB) error {
  if _, err := db.ExecContext(ctx, `create extension if not exists pgcrypto;`); err != nil {
    return fmt.Errorf("enable pgcrypto: %w", err)
  }
  entries, err := migrationFS.ReadDir("migrations")
  if err != nil { return err }
  for _, e := range entries {
    b, err := migrationFS.ReadFile("migrations/" + e.Name())
    if err != nil { return err }
    if _, err := db.ExecContext(ctx, string(b)); err != nil {
      return fmt.Errorf("migration %s: %w", e.Name(), err)
    }
  }
  return nil
}

func main() {
  dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
    mustGetEnv("DB_USER","wisp"),
    mustGetEnv("DB_PASSWORD","wisp123"),
    mustGetEnv("DB_HOST","postgres-postgresql.postgres.svc.cluster.local"),
    mustGetEnv("DB_PORT","5432"),
    mustGetEnv("DB_NAME","wispdb"),
  )

  db, err := sql.Open("pgx", dsn)
  if err != nil { log.Fatal(err) }
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
  defer cancel()
  if err := db.PingContext(ctx); err != nil { log.Fatal("db ping:", err) }
  if err := runMigrations(ctx, db); err != nil { log.Fatal("migrate:", err) }

  app := fiber.New()

  // root
  app.Get("/", func(c *fiber.Ctx) error {
    return c.SendString("Wisp backend is up ✅\nTry /health, /time, /version")
  })

  // health (reports DB too)
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

  app.Listen(":8080")
}
