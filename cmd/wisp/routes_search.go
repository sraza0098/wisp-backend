package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
)

// RegisterSearchRoutes attaches /v1/search/messages to the protected group.
func RegisterSearchRoutes(group fiber.Router, db *sql.DB) {
	// GET /v1/search/messages?q=...&roomId=...&sender=...&before=RFC3339&limit=50
	group.Get("/search/messages", func(c *fiber.Ctx) error {
		userID, err := getUserID(c)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}

		q := c.Query("q", "")
		roomID := c.Query("roomId", "")
		sender := c.Query("sender", "") // username (optional)
		beforeStr := c.Query("before", "")
		limit := 50
		if v := c.Query("limit", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}

		// Build WHERE with args; always enforce membership
		where := `rm.user_id = $1`
		args := []any{userID}
		arg := 2

		if roomID != "" {
			where += fmt.Sprintf(" AND m.room_id = $%d", arg)
			args = append(args, roomID)
			arg++
		}
		if beforeStr != "" {
			t, err := time.Parse(time.RFC3339, beforeStr)
			if err != nil {
				return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "bad before (RFC3339)"})
			}
			where += fmt.Sprintf(" AND m.created_at < $%d", arg)
			args = append(args, t)
			arg++
		}
		if sender != "" {
			// filter by sender username
			where += fmt.Sprintf(" AND u.username = $%d", arg)
			args = append(args, sender)
			arg++
		}
		// text filter
		useFTS := false
		if q != "" {
			// Use FTS when there’s more than 1 non-space char; else fallback to trigram ILIKE
			if len([]rune(q)) > 1 {
				useFTS = true
				where += fmt.Sprintf(" AND m.tsv @@ plainto_tsquery('simple', unaccent($%d))", arg)
				args = append(args, q)
				arg++
			} else {
				where += fmt.Sprintf(" AND m.body ILIKE $%d", arg)
				args = append(args, "%"+q+"%")
				arg++
			}
		}

		// Query (membership required via room_members)
		// Note: joining users for sender username display
		sqlq := fmt.Sprintf(`
			SELECT m.id, m.room_id, m.sender_id, u.username, m.kind, m.body, m.created_at
			  FROM messages m
			  JOIN room_members rm ON rm.room_id = m.room_id
			  JOIN users u ON u.id = m.sender_id
			 WHERE %s
			 ORDER BY m.created_at DESC
			 LIMIT %d
		`, where, limit)

		rows, qerr := db.QueryContext(c.Context(), sqlq, args...)
		if qerr != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		defer rows.Close()

		type msg struct {
			ID        string    `json:"id"`
			RoomID    string    `json:"roomId"`
			SenderID  string    `json:"senderId"`
			Sender    string    `json:"sender"`
			Kind      string    `json:"kind"`
			Body      string    `json:"body"`
			CreatedAt time.Time `json:"createdAt"`
		}
		var out []msg
		for rows.Next() {
			var m msg
			if err := rows.Scan(&m.ID, &m.RoomID, &m.SenderID, &m.Sender, &m.Kind, &m.Body, &m.CreatedAt); err != nil {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "scan error"})
			}
			out = append(out, m)
		}
		if items == nil { items = []msg{} }
		return c.JSON(fiber.Map{
			"items":     out,
			"usingFTS":  useFTS,
			"appliedQ":  q,
			"appliedRoomId": roomID,
		})
	})
}
