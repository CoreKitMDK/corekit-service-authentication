package authentication

import (
	"crypto/rand"
	"golang.org/x/crypto/bcrypt"
	"math/big"
)

func HashString(s string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func IsHashSameAsUnhashedString(hashed, unhashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(unhashed))
	if err != nil {
		return false
	} else {
		return true
	}
}

func GetRandomAlphanumericString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}
	return string(result), nil
}
