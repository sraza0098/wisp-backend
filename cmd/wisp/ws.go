package main

import (
	"context"
	"strings"
	"time"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// ---------- WebSocket endpoint: /ws?roomId=... ----------
func registerWebsocket(app *fiber.App, hub *wsHub, pres *Presence, jwtSecret []byte) {
	// Clients connect with a valid JWT in Sec-WebSocket-Protocol (subprotocol) as "Bearer <token>"
	app.Get("/ws", websocket.New(func(c *websocket.Conn) {
		// very small auth shim for dev: token in "Authorization" header or query
		roomID := c.Query("roomId")
		if roomID == "" {
			_ = c.Close()
			return
		}

		tokenStr := c.Cookies("token")
		if tokenStr == "" {
			// try query param or header
			tokenStr = strings.TrimSpace(strings.TrimPrefix(c.Query("token"), "Bearer "))
			if tokenStr == "" {
				tokenStr = strings.TrimSpace(strings.TrimPrefix(c.Headers("Authorization"), "Bearer "))
			}
		}
		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !tok.Valid {
			_ = c.Close()
			return
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			_ = c.Close()
			return
		}
		uid, _ := claims["sub"].(string)
		if uid == "" {
			_ = c.Close()
			return
		}

		// --- PRESENCE: mark online + join room set ---
		_ = pres.heartbeatUser(context.Background(), uid)
		_ = pres.addToRoom(context.Background(), roomID, uid)

		// keep user online while socket is open (heartbeat every pres.tick)
		stop := make(chan struct{})
		go func() {
			t := time.NewTicker(pres.tick)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					_ = pres.heartbeatUser(context.Background(), uid)
				case <-stop:
					return
				}
			}
		}()

		client := &wsClient{conn: c, send: make(chan []byte, 8), user: uid}
		hub.add(roomID, client)
		defer func() {
			// --- PRESENCE: cleanup on close ---
			close(stop)
			_ = pres.removeFromRoom(context.Background(), roomID, uid)
			pres.setLastSeen(context.Background(), uid, time.Now().UTC())
			// ----------------------------------
			hub.remove(roomID, client)
			close(client.send)
		}()

		// writer
		go func() {
			for msg := range client.send {
				if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			}
		}()

		// reader (ignore messages from client for now)
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
}
