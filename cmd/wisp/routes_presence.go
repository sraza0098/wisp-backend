package main

import (
	"database/sql"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Presence + typing endpoints
func registerPresenceRoutes(protected fiber.Router, db *sql.DB, pres *Presence) {
	// GET /v1/rooms/:roomId/presence
	protected.Get("/rooms/:roomId/presence", func(c *fiber.Ctx) error {
		_, err := getUserID(c)
		if err != nil {
			return c.SendStatus(fiber.StatusUnauthorized)
		}
		roomID := c.Params("roomId")
		users, err := pres.onlineInRoom(c.Context(), roomID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "redis error"})
		}
		return c.JSON(fiber.Map{"online": users})
	})

	// POST /v1/rooms/:roomId/typing
	protected.Post("/rooms/:roomId/typing", func(c *fiber.Ctx) error {
		userID, err := getUserID(c)
		if err != nil {
			return c.SendStatus(401)
		}

		// look up username for display (optional but nicer)
		var username string
		_ = db.QueryRowContext(c.Context(),
			`SELECT username FROM users WHERE id=$1`, userID).Scan(&username)
		if username == "" {
			username = userID
		}

		roomID := c.Params("roomId")
		if roomID == "" {
			return c.SendStatus(400)
		}

		typing.mu.Lock()
		if typing.byRoom[roomID] == nil {
			typing.byRoom[roomID] = map[string]time.Time{}
		}
		typing.byRoom[roomID][username] = time.Now().Add(3 * time.Second) // expires in 3s
		typing.mu.Unlock()

		// (optional) also broadcast to WS listeners
		// payload, _ := json.Marshal(fiber.Map{"type":"typing","roomId":roomID,"user":username,"ts":time.Now().UTC()})
		// hub.broadcast(roomID, payload)

		return c.SendStatus(204)
	})

	// GET /v1/rooms/:roomId/typing
	protected.Get("/rooms/:roomId/typing", func(c *fiber.Ctx) error {
		roomID := c.Params("roomId")
		if roomID == "" {
			return c.SendStatus(400)
		}

		now := time.Now()
		typing.mu.Lock()
		m := typing.byRoom[roomID]
		out := []string{}
		for u, exp := range m {
			if now.Before(exp) {
				out = append(out, u)
			} else {
				delete(m, u)
			}
		}
		typing.mu.Unlock()

		return c.JSON(out)
	})
}
