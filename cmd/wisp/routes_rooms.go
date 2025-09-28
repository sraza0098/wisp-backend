package main

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Create, list, join rooms
func registerRoomRoutes(protected fiber.Router, db *sql.DB) {
	// Create room
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

	// Join room (idempotent)
	protected.Post("/rooms/:roomId/join", func(c *fiber.Ctx) error {
		userID, err := getUserID(c)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		roomID := c.Params("roomId")
		if roomID == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing roomId"})
		}

		var exists bool
		if err := db.QueryRowContext(c.Context(),
			`SELECT EXISTS (SELECT 1 FROM rooms WHERE id=$1)`, roomID).Scan(&exists); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		if !exists {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "room not found"})
		}

		if _, err := db.ExecContext(c.Context(),
			`INSERT INTO room_members(room_id,user_id) VALUES ($1,$2)
			ON CONFLICT (room_id,user_id) DO NOTHING`, roomID, userID); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		return c.SendStatus(http.StatusNoContent)
	})
}
