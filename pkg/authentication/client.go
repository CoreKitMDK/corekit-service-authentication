package authentication

import "net/http"

type IClient interface {
	Close()
	LoginPassword(req *LoginPasswordRequest) (*LoginPasswordResponse, error)
	LoginRefreshToken(req *LoginRefreshTokenRequest) (*LoginRefreshTokenResponse, error)
	RegisterPassword(req *RegisterPasswordRequest) (*RegisterPasswordResponse, error)
	RefreshToken(req *RefreshTokenRequest) (*RefreshTokenResponse, error)
	LogoutToken(req *LogoutTokenRequest) (*LogoutTokenResponse, error)
	LogoutRefreshToken(req *LogoutRefreshTokenRequest) (*LogoutRefreshTokenResponse, error)
	LogoutAll(req *LogoutAllRequest) (*LogoutAllResponse, error)
	GetVerificationCode(req *GetVerificationCodeRequest) (*GetVerificationCodeResponse, error)
	VerifyEntity(req *VerifyEntityRequest) (*VerifyEntityResponse, error)
	ForgotPassword(req *ForgotPasswordRequest) (*ForgotPasswordResponse, error)
	ChangePassword(req *ChangePasswordRequest) (*ChangePasswordResponse, error)
	DeleteEntity(req *DeleteEntityRequest) (*DeleteEntityResponse, error)
	GetEntityDetails(req *GetEntityDetailsRequest) (*GetEntityDetailsResponse, error)
}

type Client struct {
	httpClient http.Client
	namespace  string
	hostname   string
	Tags       map[string]string
}
