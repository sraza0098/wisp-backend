package main

import (
	"sync"

	"github.com/gofiber/contrib/websocket"
)

type wsClient struct {
	conn *websocket.Conn
	send chan []byte
	user string
}

type wsHub struct {
	mu    sync.RWMutex
	rooms map[string]map[*wsClient]struct{}
}

func newHub() *wsHub {
	return &wsHub{rooms: make(map[string]map[*wsClient]struct{})}
}

func (h *wsHub) add(room string, c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rooms[room] == nil {
		h.rooms[room] = make(map[*wsClient]struct{})
	}
	h.rooms[room][c] = struct{}{}
}

func (h *wsHub) remove(room string, c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m, ok := h.rooms[room]; ok {
		delete(m, c)
		if len(m) == 0 {
			delete(h.rooms, room)
		}
	}
}

func (h *wsHub) broadcast(room string, payload []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.rooms[room] {
		select {
		case c.send <- payload:
		default: /* drop if slow */
		}
	}
}
