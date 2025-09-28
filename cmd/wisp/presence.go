package main

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Presence struct {
	rdb  *redis.Client
	ttl  time.Duration
	tick time.Duration
}

func NewPresence(r *redis.Client, ttl, tick time.Duration) *Presence {
	return &Presence{rdb: r, ttl: ttl, tick: tick}
}

// keys:
//   pres:user:{userId} = "1" (EX ttl)
//   pres:room:{roomId} = Set of userIds (no TTL, cleaned on fetch)
//   lastseen:{userId}   = timestamp (string RFC3339) for quick peek (optional)
func (p *Presence) heartbeatUser(ctx context.Context, userId string) error {
	return p.rdb.Set(ctx, "pres:user:"+userId, "1", p.ttl).Err()
}
func (p *Presence) addToRoom(ctx context.Context, roomId, userId string) error {
	return p.rdb.SAdd(ctx, "pres:room:"+roomId, userId).Err()
}
func (p *Presence) removeFromRoom(ctx context.Context, roomId, userId string) error {
	return p.rdb.SRem(ctx, "pres:room:"+roomId, userId).Err()
}
func (p *Presence) onlineInRoom(ctx context.Context, roomId string) ([]string, error) {
	users, err := p.rdb.SMembers(ctx, "pres:room:"+roomId).Result()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(users))
	for _, u := range users {
		exists, _ := p.rdb.Exists(ctx, "pres:user:"+u).Result()
		if exists == 1 {
			out = append(out, u)
		} else {
			// cleanup stale
			_ = p.rdb.SRem(ctx, "pres:room:"+roomId, u).Err()
		}
	}
	return out, nil
}
func (p *Presence) setLastSeen(ctx context.Context, userId string, t time.Time) {
	_ = p.rdb.Set(ctx, "lastseen:"+userId, t.Format(time.RFC3339), 0).Err()
}
