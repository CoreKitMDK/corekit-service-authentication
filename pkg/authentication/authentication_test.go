package authentication

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"testing"
)

func TestDal(t *testing.T) {

	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer dal.Close()

	res, err := dal.RegisterPassword(context.Background(), &RegisterPasswordRequest{
		Password:          "1234",
		PrimaryEmail:      "1234@email.com",
		PublicIdentifier:  "test",
		PrimaryPhone:      nil,
		IPAddress:         nil,
		UserAgent:         nil,
		DeviceFingerprint: nil,
	})

	if err != nil {
		t.Fatal(err)
	}

	if !res.Valid || res.Error != "" {
		t.Fatal("expected invalid response")
	}

}

func TestLoginPassword(t *testing.T) {
	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer dal.Close()

	req := LoginPasswordRequest{
		Identifier:        "1234@email.com", //"117d7c6c-84bb-4381-ad93-5ec5356df38e",
		Password:          "1234",
		IPAddress:         nil,
		UserAgent:         nil,
		DeviceFingerprint: nil,
	}

	res, err := dal.LoginPassword(context.Background(), &req)

	if err != nil {
		t.Fatal(err)
	}

	if !res.Valid || res.Error != "" {
		t.Fatal("expected invalid response")
	}

	fmt.Println(res.Token)
	fmt.Println(res.RefreshToken)
}

// token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Rlc3QuY29tIiwic3ViIjoiMTE3ZDdjNmMtODRiYi00MzgxLWFkOTMtNWVjNTM1NmRmMzhlIiwiZXhwIjoxNzU0NzYyODM4LCJuYmYiOjE3NTIxNzA4NDIsImlhdCI6MTc1MjE3MDg0MiwianRpIjoidkZOZVZCMzhHeE1RcHM2MElmclZRV2Nqek8wZHp5eTgifQ.Dxgb5BfpDr3QdfFFvAOTzzvhSOUkdqLIW9sJCA9JwN4"

var entity string = "117d7c6c-84bb-4381-ad93-5ec5356df38e"
var refreshToken string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Rlc3QuY29tIiwic3ViIjoiMTE3ZDdjNmMtODRiYi00MzgxLWFkOTMtNWVjNTM1NmRmMzhlIiwiZXhwIjoxNzU0NzYyODM4LCJuYmYiOjE3NTIxNzA4MzgsImlhdCI6MTc1MjE3MDgzOCwianRpIjoic0R2MG5FejE1VnVHM3laQ3cwbFNHZkVadTgzNFJteTcifQ.gtI6Yh4tvw-MXiG2D6HFvSg1Z35Offps1QTgyOZwOQg"

func TestLoginRefreshToken(t *testing.T) {
	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer dal.Close()

	enUuid, err := uuid.Parse(entity)
	if err != nil {
		t.Fatal(err)
	}

	req := LoginRefreshTokenRequest{
		Entity:       enUuid,
		RefreshToken: refreshToken,
	}

	res, err := dal.LoginRefreshToken(context.Background(), &req)

	if err != nil {
		t.Fatal(err)
	}

	if !res.Valid || res.Error != "" {
		t.Fatal("expected invalid response")
	}

	fmt.Println(res.Token)
	fmt.Println(res.Entity)

}

func TestRefreshToken(t *testing.T) {
	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer dal.Close()

	enUuid, err := uuid.Parse(entity)
	if err != nil {
		t.Fatal(err)
	}

	req := RefreshTokenRequest{
		Entity:       enUuid,
		RefreshToken: refreshToken,
	}

	res, err := dal.RefreshToken(context.Background(), &req)

	if err != nil {
		t.Fatal(err)
	}

	if !res.Valid || res.Error != "" {
		t.Fatal("expected invalid response")
	}

	fmt.Println(res.Token)
	fmt.Println(res.Entity)
}

func TestLogout(t *testing.T) {
	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer dal.Close()

	enUuid, err := uuid.Parse(entity)
	if err != nil {
		t.Fatal(err)
	}

	reqToken := LogoutTokenRequest{
		Token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Rlc3QuY29tIiwic3ViIjoiMTE3ZDdjNmMtODRiYi00MzgxLWFkOTMtNWVjNTM1NmRmMzhlIiwiZXhwIjoxNzUyMTcyNzU4LCJuYmYiOjE3NTIxNzE4NTgsImlhdCI6MTc1MjE3MTg1OCwianRpIjoiZ21haE40WGRLWm5CZ3g2aVppNVNkWGpQbTZXOHR4RUwifQ.1ybiLmQhimlbb-atOZWXSVGUEIumjwvGtXQATTK141o",
		Entity: enUuid,
	}

	reqRefreshToken := LogoutRefreshTokenRequest{
		RefreshToken: refreshToken,
		Entity:       enUuid,
	}

	resToken, err := dal.LogoutToken(context.Background(), &reqToken)
	if err != nil {
		//t.Fatal(err)
		fmt.Println(err)
	}

	if !resToken.Valid || resToken.Error != "" {
		//t.Fatal("expected invalid response")
		fmt.Println(resToken.Error)
	}

	resRefreshToken, err := dal.LogoutRefreshToken(context.Background(), &reqRefreshToken)
	if err != nil {
		fmt.Println(err)
		//t.Fatal(err)
	}

	if !resRefreshToken.Valid || resRefreshToken.Error != "" {
		fmt.Println(resToken.Error)
		//t.Fatal("expected invalid response")
	}

	reqLogoutAll := LogoutAllRequest{
		Entity: enUuid,
	}

	resLogoutAll, err := dal.LogoutAll(context.Background(), &reqLogoutAll)
	if err != nil {
		t.Fatal(err)
	}

	if !resLogoutAll.Valid || resLogoutAll.Error != "" {
		t.Fatal("expected invalid response")
	}
}

func TestVerify(t *testing.T) {
	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer dal.Close()

	enUuid, err := uuid.Parse(entity)
	if err != nil {
		t.Fatal(err)
	}

	reqGetVerifiactionCode := GetVerificationCodeRequest{
		Entity: enUuid,
	}

	resGetVerifiactionCode, err := dal.GetVerificationCode(context.Background(), &reqGetVerifiactionCode)
	if err != nil {
		fmt.Println(err)
		//t.Fatal(err)
	}

	if !resGetVerifiactionCode.Valid || resGetVerifiactionCode.Error != "" {
		fmt.Println(resGetVerifiactionCode.Error)
	}

	fmt.Println(resGetVerifiactionCode.Code)

	reqVerify := VerifyEntityRequest{
		Entity: enUuid,
		Code:   resGetVerifiactionCode.Code,
	}

	resVerifyEntity, err := dal.VerifyEntity(context.Background(), &reqVerify)
	if err != nil {
		fmt.Println(err)
	}

	if !resVerifyEntity.Valid || resVerifyEntity.Error != "" {
		fmt.Println(resVerifyEntity.Error)
	}
}

func TestChangePassword(t *testing.T) {
	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer dal.Close()

	reqForgotPassword := ForgotPasswordRequest{
		PrimaryEmail: "1234@email.com",
	}

	resForgotPassword, err := dal.ForgotPassword(context.Background(), &reqForgotPassword)
	if err != nil {
		fmt.Println(err)
	}

	if !resForgotPassword.Valid || resForgotPassword.Error != "" {
		fmt.Println(resForgotPassword.Error)
	}

	fmt.Println(resForgotPassword.PasswordResetToken)

	reqChangePassword := ChangePasswordRequest{
		PrimaryEmail:       "1234@email.com",
		PasswordResetToken: resForgotPassword.PasswordResetToken,
		Password:           "4321",
		IPAddress:          nil,
		UserAgent:          nil,
		DeviceFingerprint:  nil,
	}

	resChangePassword, err := dal.ChangePassword(context.Background(), &reqChangePassword)
	if err != nil {
		fmt.Println(err)
	}

	if !resChangePassword.Valid || resChangePassword.Error != "" {
		fmt.Println(resChangePassword.Error)
	}

}

func TestGetEntityDetail(t *testing.T) {
	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer dal.Close()

	enUuid, err := uuid.Parse(entity)
	if err != nil {
		t.Fatal(err)
	}

	reqGetEntityDetail := GetEntityDetailsRequest{
		Entity: enUuid,
	}

	res, err := dal.GetEntityDetails(context.Background(), &reqGetEntityDetail)
	if err != nil {
		t.Fatal(err)
	}

	if !res.Valid || res.Error != "" {
		t.Fatal("expected invalid response")
	}

	fmt.Println(res.Entity)
}

func TestDeleteEntity(t *testing.T) {
	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer dal.Close()

	enUuid, err := uuid.Parse(entity)
	if err != nil {
		t.Fatal(err)
	}

	reqDeleteEntity := DeleteEntityRequest{
		Entity: enUuid,
		Reason: "Test",
	}

	res, err := dal.DeleteEntity(context.Background(), &reqDeleteEntity)
	if err != nil {
		t.Fatal(err)
	}

	if !res.Valid || res.Error != "" {
		t.Fatal("expected invalid response")
	}

	fmt.Println(res.Entity)
}
