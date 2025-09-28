package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	_ "github.com/jackc/pgx/v5/stdlib"
)

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
		time.Duration(func() int { if v, _ := strconv.Atoi(env("PRESENCE_TTL_SECONDS", "60")); v > 0 { return v }; return 60 }())*time.Second,
		time.Duration(func() int { if v, _ := strconv.Atoi(env("PRESENCE_TICK_SECONDS", "20")); v > 0 { return v }; return 20 }())*time.Second,
	)

	// --- App + hub ---
	app := fiber.New()
	hub := newHub()

	// Base + auth + protected routes
	registerBaseRoutes(app, db)
	protected := registerAuthRoutes(app, db, jwtSecret)
	registerRoomRoutes(protected, db)
	registerPresenceRoutes(protected, db, pres)
	registerMessageRoutes(protected, db, hub)
	RegisterSearchRoutes(protected, db)
	// WebSocket
	registerWebsocket(app, hub, pres, jwtSecret)

	// ---- LISTEN LAST ----
	log.Fatal(app.Listen(":" + env("PORT", "8080")))
}
