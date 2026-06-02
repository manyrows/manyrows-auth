package core

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type AccountEmailOTP struct {
	ID        uuid.UUID  `json:"id"`
	AccountID uuid.UUID  `json:"accountId"`
	CodeHash  string     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	Attempts  int        `json:"-"`
	CreatedAt time.Time  `json:"createdAt"`
}

func (o *AccountEmailOTP) IsUsed() bool {
	return o != nil && o.UsedAt != nil && !o.UsedAt.IsZero()
}

func (o *AccountEmailOTP) IsExpired(now time.Time) bool {
	if o == nil {
		return true
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !o.ExpiresAt.After(now)
}

func (o *AccountEmailOTP) IsActive(now time.Time) bool {
	if o == nil {
		return false
	}
	return !o.IsUsed() && !o.IsExpired(now)
}

type AccountPasswordResetOTP struct {
	ID        uuid.UUID  `json:"id"`
	AccountID uuid.UUID  `json:"accountId"`
	CodeHash  string     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	Attempts  int        `json:"-"`
	CreatedAt time.Time  `json:"createdAt"`
}

func (o *AccountPasswordResetOTP) IsUsed() bool {
	return o != nil && o.UsedAt != nil && !o.UsedAt.IsZero()
}

func (o *AccountPasswordResetOTP) IsExpired(now time.Time) bool {
	if o == nil {
		return true
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !o.ExpiresAt.After(now)
}

func (o *AccountPasswordResetOTP) IsActive(now time.Time) bool {
	if o == nil {
		return false
	}
	return !o.IsUsed() && !o.IsExpired(now)
}

type AccountEmailChangeOTP struct {
	ID        uuid.UUID  `json:"id"`
	AccountID uuid.UUID  `json:"accountId"`
	NewEmail  string     `json:"newEmail"`
	CodeHash  string     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	Attempts  int        `json:"-"`
	CreatedAt time.Time  `json:"createdAt"`
}

func (o *AccountEmailChangeOTP) IsUsed() bool {
	return o != nil && o.UsedAt != nil && !o.UsedAt.IsZero()
}

func (o *AccountEmailChangeOTP) IsExpired(now time.Time) bool {
	if o == nil {
		return true
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !o.ExpiresAt.After(now)
}

func (o *AccountEmailChangeOTP) IsActive(now time.Time) bool {
	if o == nil {
		return false
	}
	return !o.IsUsed() && !o.IsExpired(now)
}
