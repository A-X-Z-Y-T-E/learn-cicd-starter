package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKeyMissingHeader(t *testing.T) {
	headers := http.Header{}

	key, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}

	if key != "" {
		t.Fatalf("expected empty key, got %q", key)
	}
}

func TestGetAPIKeyMalformedHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"missing_prefix", "12345"},
		{"wrong_prefix", "Bearer 12345"},
		{"only_prefix", "ApiKey"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tt.header)

			key, err := GetAPIKey(headers)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}

			if err.Error() != "malformed authorization header" {
				t.Fatalf("expected malformed authorization header error, got %v", err)
			}

			if key != "" {
				t.Fatalf("expected empty key, got %q", key)
			}
		})
	}
}

func TestGetAPIKeySuccess(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey secret-key-value")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key != "secret-key-value" {
		t.Fatalf("expected key %q, got %q", "secret-key-value", key)
	}
}
