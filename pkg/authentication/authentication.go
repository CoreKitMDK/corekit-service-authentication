package authentication

import (
	"context"
	"github.com/jackc/pgx/v5"
)

type DAL struct {
	db *pgx.Conn
}

func NewAuthenticationDAL(connString string) (*DAL, error) {
	conn, err := pgx.Connect(context.Background(), connString)
	if err != nil {
		return nil, err
	}
	return &DAL{db: conn}, nil
}

func (dal *DAL) Close() {
	err := dal.db.Close(context.Background())
	if err != nil {
		return
	}
}

func (dal *DAL) LoginPassword(req *LoginPasswordRequest) (*LoginPasswordResponse, error) {
	return nil, nil
}

func (dal *DAL) LoginRefreshToken(req *LoginRefreshTokenRequest) (*LoginRefreshTokenResponse, error) {
	return nil, nil
}

func (dal *DAL) RegisterPassword(req *RegisterPasswordRequest) (*RegisterPasswordResponse, error) {
	return nil, nil
}

func (dal *DAL) RefreshToken(req *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	return nil, nil
}

func (dal *DAL) LogoutToken(req *LogoutTokenRequest) (*LogoutTokenResponse, error) {
	return nil, nil
}

func (dal *DAL) LogoutRefreshToken(req *LogoutRefreshTokenRequest) (*LogoutRefreshTokenResponse, error) {
	return nil, nil
}

func (dal *DAL) LogoutAll(req *LogoutAllRequest) (*LogoutAllResponse, error) {
	return nil, nil
}

func (dal *DAL) GetVerificationCode(req *GetVerificationCodeRequest) (*GetVerificationCodeResponse, error) {
	return nil, nil
}

func (dal *DAL) VerifyEntity(req *VerifyEntityRequest) (*VerifyEntityResponse, error) {
	return nil, nil
}

func (dal *DAL) ForgotPassword(req *ForgotPasswordRequest) (*ForgotPasswordResponse, error) {
	return nil, nil
}

func (dal *DAL) ChangePassword(req *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	return nil, nil
}

func (dal *DAL) DeleteEntity(req *DeleteEntityRequest) (*DeleteEntityResponse, error) {
	return nil, nil
}

func (dal *DAL) GetUserDetails(req *GetUserDetailsRequest) (*GetUserDetailsResponse, error) {
	return nil, nil
}
