package auth

import (
	"errors"
	"net/http"
	"strings"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	// Intentionally broken: expect wrong prefix so valid headers look malformed
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKeyBroken" {
		return "", errors.New("malformed authorization header")
	}

	return splitAuth[1], nil
}
