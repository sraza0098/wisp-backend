package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Messages, reads, recent
func registerMessageRoutes(protected fiber.Router, db *sql.DB, hub *wsHub) {
	// Send message
	protected.Post("/rooms/:roomId/messages", func(c *fiber.Ctx) error {
		userID, err := getUserID(c)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		roomID := c.Params("roomId")
		if roomID == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing roomId"})
		}

		var member bool
		if err := db.QueryRowContext(c.Context(),
			`SELECT EXISTS (SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2)`,
			roomID, userID).Scan(&member); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		if !member {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "join room first"})
		}

		var req struct{ Body, Kind string }
		if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Body) == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "body required"})
		}
		if req.Kind == "" {
			req.Kind = "text"
		}

		if _, err := db.ExecContext(c.Context(),
			`INSERT INTO messages(room_id, sender_id, kind, body) VALUES ($1,$2,$3,$4)`,
			roomID, userID, req.Kind, req.Body); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		payload, _ := json.Marshal(fiber.Map{
			"type":   "message",
			"roomId": roomID,
			"from":   userID,
			"kind":   req.Kind,
			"body":   req.Body,
			"ts":     time.Now().UTC(),
		})
		hub.broadcast(roomID, payload)

		return c.SendStatus(http.StatusCreated)
	})

	// List messages in a room
	protected.Get("/rooms/:roomId/messages", func(c *fiber.Ctx) error {
		userID, err := getUserID(c)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		roomID := c.Params("roomId")
		if roomID == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing roomId"})
		}

		var member bool
		if err := db.QueryRowContext(c.Context(),
			`SELECT EXISTS (SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2)`,
			roomID, userID).Scan(&member); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		if !member {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "join room first"})
		}

		limit := 50
		if v := c.Query("limit", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}
		beforeStr := c.Query("before", "")

		var rows *sql.Rows
		var qerr error
		if beforeStr != "" {
			t, err := time.Parse(time.RFC3339, beforeStr)
			if err != nil {
				return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "bad before (RFC3339)"})
			}
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
		if qerr != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		defer rows.Close()

		type msg struct{ ID, RoomID, SenderID, Sender, Kind, Body string; CreatedAt time.Time }
		var items []msg
		for rows.Next() {
			var m msg
			if err := rows.Scan(&m.ID, &m.RoomID, &m.SenderID, &m.Sender, &m.Kind, &m.Body, &m.CreatedAt); err != nil {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "scan error"})
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

	// POST /v1/rooms/:roomId/read  { "messageId":"uuid" }
	protected.Post("/rooms/:roomId/read", func(c *fiber.Ctx) error {
		userID, err := getUserID(c)
		if err != nil {
			return c.SendStatus(fiber.StatusUnauthorized)
		}
		roomID := c.Params("roomId")
		var req struct{ MessageID string `json:"messageId"` }
		if err := c.BodyParser(&req); err != nil || req.MessageID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "messageId required"})
		}
		_, err = db.ExecContext(c.Context(),
			`INSERT INTO message_reads(message_id, user_id, room_id)
			VALUES ($1,$2,$3)
			ON CONFLICT (message_id,user_id) DO UPDATE SET read_at = EXCLUDED.read_at`,
			req.MessageID, userID, roomID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "db error"})
		}
		return c.SendStatus(204)
	})

	// GET /v1/messages/:messageId/reads
	protected.Get("/messages/:messageId/reads", func(c *fiber.Ctx) error {
		_, err := getUserID(c)
		if err != nil {
			return c.SendStatus(fiber.StatusUnauthorized)
		}
		mid := c.Params("messageId")
		rows, qerr := db.QueryContext(c.Context(),
			`SELECT user_id, read_at FROM message_reads WHERE message_id=$1 ORDER BY read_at DESC`, mid)
		if qerr != nil {
			return c.Status(500).JSON(fiber.Map{"error": "db error"})
		}
		defer rows.Close()
		type rr struct{ UserID string `json:"userId"`; ReadAt time.Time `json:"readAt"` }
		out := []rr{}
		for rows.Next() {
			var x rr
			if err := rows.Scan(&x.UserID, &x.ReadAt); err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "scan"})
			}
			out = append(out, x)
		}
		return c.JSON(out)
	})

	// Recent messages for the user
	protected.Get("/messages/recent", func(c *fiber.Ctx) error {
		userID, err := getUserID(c)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		limit := 50
		if v := c.Query("limit", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}
		rows, qerr := db.QueryContext(c.Context(),
			`SELECT m.id, m.room_id, m.sender_id, u.username, m.kind, m.body, m.created_at
			 FROM messages m
			 JOIN room_members rm ON rm.room_id = m.room_id AND rm.user_id = $1
			 JOIN users u ON u.id = m.sender_id
			 ORDER BY m.created_at DESC LIMIT $2`, userID, limit)
		if qerr != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		defer rows.Close()

		type msg struct {
			ID, RoomID, SenderID, Sender, Kind, Body string
			CreatedAt                                 time.Time
		}
		var out []msg
		for rows.Next() {
			var m msg
			if err := rows.Scan(&m.ID, &m.RoomID, &m.SenderID, &m.Sender, &m.Kind, &m.Body, &m.CreatedAt); err != nil {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "scan error"})
			}
			out = append(out, m)
		}
		return c.JSON(out)
	})
}
