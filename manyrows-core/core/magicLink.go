package core

import "time"

type MagicLink struct {
	ID        string
	Purpose   string
	Email     string
	ExpiresAt time.Time
	UsedAt    *time.Time
}
