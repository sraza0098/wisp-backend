package main

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	jwtware "github.com/gofiber/jwt/v3"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

type userRow struct {
	ID           string
	Username     string
	PasswordHash string
}

// Registers /v1/users, /v1/login, and returns the protected /v1 group.
func registerAuthRoutes(app *fiber.App, db *sql.DB, jwtSecret []byte) fiber.Router {
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
		_, err = db.ExecContext(c.Context(),
			`INSERT INTO users (username, password_hash) VALUES ($1, $2)`,
			req.Username, string(hash),
		)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "username exists"})
			}
			log.Printf("signup db error: %v", err)
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
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
			SigningKey:  jwtSecret,
			ContextKey:  "jwt",
			ErrorHandler: func(c *fiber.Ctx, err error) error {
				return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
			},
		}),
	)

	return protected
}
