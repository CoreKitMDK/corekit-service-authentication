package authentication

import "github.com/google/uuid"

type LoginPasswordRequest struct {
	Identifier   string `json:"identifier"`
	PasswordHash string `json:"password_hash"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type LoginRefreshTokenRequest struct {
	Entity       uuid.UUID `json:"entity"`
	RefreshToken string    `json:"refresh_token"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type RegisterPasswordRequest struct {
	Identifier       string  `json:"identifier"`
	Password         string  `json:"password"`
	PrimaryEmail     string  `json:"primary_email"`
	PublicIdentifier string  `json:"public_identifier"`
	PrimaryPhone     *string `json:"primary_phone,omitempty"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

// Get new token with refresh token
type RefreshTokenRequest struct {
	Entity       uuid.UUID `json:"entity"`
	RefreshToken string    `json:"refresh_token"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type LogoutTokenRequest struct {
	Entity uuid.UUID `json:"entity"`
	Token  string    `json:"token"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type LogoutRefreshTokenRequest struct {
	Entity       uuid.UUID `json:"entity"`
	RefreshToken string    `json:"refresh_token"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type LogoutAllRequest struct {
	Entity uuid.UUID `json:"entity"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type GetVerificationCodeRequest struct {
	Entity uuid.UUID `json:"entity"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type VerifyEntityRequest struct {
	Entity uuid.UUID `json:"entity"`
	Code   string    `json:"code"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type ForgotPasswordRequest struct {
	PrimaryEmail string `json:"primary_email"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type ChangePasswordRequest struct {
	PrimaryEmail       string `json:"primary_email"`
	PasswordResetToken string `json:"password_reset_token"`
	Password           string `json:"password"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type DeleteEntityRequest struct {
	Entity uuid.UUID `json:"entity"`
	Reason string    `json:"reason"`

	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

type GetEntityDetailsRequest struct {
	Entity uuid.UUID `json:"entity"`
}
