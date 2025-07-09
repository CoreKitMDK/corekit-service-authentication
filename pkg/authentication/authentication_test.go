package authentication

import (
	"context"
	"testing"
)

func TestDal(t *testing.T) {

	// --host=internal-authorization-db-rw.testing-dev --dbname=app  --user=internal-authorization-db-app-user
	connStr := "user=internal-authentication-db-app-user password=internal-authentication-db-app-user host=internal-authentication-db-rw.testing-dev port=5432 dbname=app sslmode=disable"

	dal, err := NewAuthenticationDAL(connStr, "https://test.com", make([]string, 0), "1234")
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

	if res.Valid || res.Error != "" {
		t.Fatal("expected invalid response")
	}

}
