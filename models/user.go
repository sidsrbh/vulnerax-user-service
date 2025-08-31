package models

import "time"

// UserProfile mirrors /users/{uid}
type UserProfile struct {
	Email      string    `json:"email"`
	CreatedAt  time.Time `json:"created_at"`
	UsageCount int       `json:"usage_count"`
	Plan       string    `json:"plan"`
}

// Subscription mirrors /subscriptions/{uid}
type Subscription struct {
	Plan        string    `json:"plan"`
	PurchasedAt time.Time `json:"purchased_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RazorpayID  string    `json:"razorpay_id"`
}
