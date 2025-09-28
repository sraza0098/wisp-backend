package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func registerBaseRoutes(app *fiber.App, db *sql.DB) {
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

	// route dump (dev)
	go func() {
		time.Sleep(200 * time.Millisecond)
		b, _ := json.MarshalIndent(app.GetRoutes(), "", "  ")
		log.Printf("ROUTES:\n%s\n", string(b))
	}()
	app.Get("/__routes", func(c *fiber.Ctx) error { return c.JSON(app.GetRoutes()) })
}

// helper: get user ID (sub) from Authorization header (version-agnostic)
func getUserID(c *fiber.Ctx) (string, error) {
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
