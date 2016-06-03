package util

import (
	"crypto/rand"
	"encoding/base64"
)

// RandomString generates a random string
func RandomString(s int) (string, error) {
	b := make([]byte, s)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}
