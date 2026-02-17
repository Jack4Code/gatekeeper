package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GenerateRefreshToken generates a cryptographically random opaque refresh token.
// Returns the plaintext token (to send to client) and its SHA-256 hash (to store in DB).
func GenerateRefreshToken() (plaintext string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	plaintext = hex.EncodeToString(b)
	hash = sha256Hex(plaintext)
	return plaintext, hash, nil
}

// sha256Hex returns the hex-encoded SHA-256 hash of the input string.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
