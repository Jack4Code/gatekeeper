package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims extends JWT claims to include roles and permissions
type CustomClaims struct {
	jwt.RegisteredClaims
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// GenerateJWTWithRoles creates a JWT token with user ID, email, roles, and permissions
func GenerateJWTWithRoles(userID, email string, roles, permissions []string, secret string, expiration time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("JWT secret cannot be empty")
	}

	now := time.Now()
	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
		},
		UserID:      userID,
		Email:       email,
		Roles:       roles,
		Permissions: permissions,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateJWTWithRoles validates a JWT token and extracts custom claims
func ValidateJWTWithRoles(tokenString, secret string) (*CustomClaims, error) {
	if secret == "" {
		return nil, fmt.Errorf("JWT secret cannot be empty")
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// Helper function to format permissions as "resource:action" strings
func formatPermissions(permissions []struct{ Resource, Action string }) []string {
	result := make([]string, len(permissions))
	for i, p := range permissions {
		result[i] = fmt.Sprintf("%s:%s", p.Resource, p.Action)
	}
	return result
}
