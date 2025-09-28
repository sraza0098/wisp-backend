package main

import (
	"sync"
	"time"
)

type typingState struct {
	mu     sync.Mutex
	byRoom map[string]map[string]time.Time // roomID -> username -> expiresAt
}

var typing = typingState{byRoom: map[string]map[string]time.Time{}}
