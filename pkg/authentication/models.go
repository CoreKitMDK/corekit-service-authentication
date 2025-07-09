package authentication

import (
	"github.com/google/uuid"
)

type Entity struct {
	ID                         uuid.UUID `json:"id"`
	PrimaryEmail               string    `json:"primary_email"`
	PrimaryPhone               *string   `json:"primary_phone,omitempty"`
	IsVerified                 bool      `json:"is_verified"`
	VerificationToken          *string   `json:"verification_token,omitempty"`
	VerificationTokenExpiresAt *int64    `json:"verification_token_expires_at,omitempty"`
	PublicIdentifier           string    `json:"public_identifier"`
	Active                     bool      `json:"active"`
	CreatedAt                  int64     `json:"created_at"`
	DeletedAt                  *int64    `json:"deleted_at,omitempty"`
}

type EntityToken struct {
	ID                uuid.UUID `json:"id"`
	EntityID          uuid.UUID `json:"entity_id"`
	RefreshTokenID    uuid.UUID `json:"refresh_token_id"`
	Token             string    `json:"token"`
	TokenRandomID     string    `json:"token_random_id"`
	IPAddress         *string   `json:"ip_address,omitempty"`
	UserAgent         *string   `json:"user_agent,omitempty"`
	DeviceFingerprint *string   `json:"device_fingerprint,omitempty"`
	UsageCount        int       `json:"usage_count"`
	LastUsedAt        *int64    `json:"last_used_at,omitempty"`
	CreatedAt         int64     `json:"created_at"`
	ExpiresAt         int64     `json:"expires_at"`
	RevokedAt         *int64    `json:"revoked_at,omitempty"`
	Active            bool      `json:"active"`
}

type EntityRefreshToken struct {
	ID                uuid.UUID `json:"id"`
	EntityID          uuid.UUID `json:"entity_id"`
	Token             string    `json:"token"`
	TokenRandomID     string    `json:"token_random_id"`
	IPAddress         *string   `json:"ip_address,omitempty"`
	UserAgent         *string   `json:"user_agent,omitempty"`
	DeviceFingerprint *string   `json:"device_fingerprint,omitempty"`
	UsageCount        int       `json:"usage_count"`
	LastUsedAt        *int64    `json:"last_used_at,omitempty"`
	CreatedAt         int64     `json:"created_at"`
	ExpiresAt         int64     `json:"expires_at"`
	RevokedAt         *int64    `json:"revoked_at,omitempty"`
	Active            bool      `json:"active"`
}

type EntityLoginMethod struct {
	ID         uuid.UUID `json:"id"`
	EntityID   uuid.UUID `json:"entity_id"`
	MethodID   uuid.UUID `json:"method_id"`
	MethodType string    `json:"method_type"`
	Active     bool      `json:"active"`
	CreatedAt  int64     `json:"created_at"`
	DeletedAt  *int64    `json:"deleted_at,omitempty"`
}

type EntityLoginMethodPassword struct {
	ID                          uuid.UUID
	Identifier                  string
	PasswordHash                string
	PasswordResetToken          *string
	PasswordResetTokenExpiresAt *int64
	Active                      bool
	CreatedAt                   int64
	DeletedAt                   *int64
}
