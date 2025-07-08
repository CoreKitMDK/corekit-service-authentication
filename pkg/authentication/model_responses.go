package authentication

import "github.com/google/uuid"

type LoginPasswordResponse struct {
	Entity uuid.UUID `json:"entity"`

	Token          string `json:"token"`
	TokenExpiresAt int64  `json:"token_expires_at"`

	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresAt int64  `json:"refresh_token_expires_at"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type LoginRefreshTokenResponse struct {
	Entity uuid.UUID `json:"entity"`

	Token          string `json:"token"`
	TokenExpiresAt int64  `json:"token_expires_at"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type RegisterPasswordResponse struct {
	Entity uuid.UUID `json:"entity"`

	Token          string `json:"token"`
	TokenExpiresAt int64  `json:"token_expires_at"`

	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresAt int64  `json:"refresh_token_expires_at"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type RefreshTokenResponse struct {
	Entity uuid.UUID `json:"entity"`

	Token          string `json:"token"`
	TokenExpiresAt int64  `json:"token_expires_at"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type LogoutTokenResponse struct {
	Entity uuid.UUID `json:"entity"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type LogoutRefreshTokenResponse struct {
	Entity uuid.UUID `json:"entity"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type LogoutAllResponse struct {
	Entity uuid.UUID `json:"entity"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type GetVerificationCodeResponse struct {
	Entity uuid.UUID `json:"entity"`
	Code   string    `json:"code"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type VerifyEntityResponse struct {
	Entity uuid.UUID `json:"entity"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type ForgotPasswordResponse struct {
	Entity             uuid.UUID `json:"entity"`
	PasswordResetToken string    `json:"password_reset_token"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type ChangePasswordResponse struct {
	Entity uuid.UUID `json:"entity"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type DeleteEntityResponse struct {
	Entity uuid.UUID `json:"entity"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type GetEntityDetailsResponse struct {
	Entity *Entity `json:"user"`

	Valid bool   `json:"valid"`
	Error string `json:"error"`
}
