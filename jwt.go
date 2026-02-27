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
	AccountID   string   `json:"account_id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// GenerateJWTWithRoles creates a JWT token with user ID, account ID, email, roles, and permissions
func GenerateJWTWithRoles(userID, accountID, email string, roles, permissions []string, secret string, expiration time.Duration) (string, error) {
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
		AccountID:   accountID,
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

// IDTokenClaims contains identity-only claims for the ID token
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
	Name  string `json:"name"`
}

// GenerateIDToken creates a JWT ID token with identity claims (no roles/permissions)
func GenerateIDToken(userID, email, name, secret string, expiration time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("JWT secret cannot be empty")
	}

	now := time.Now()
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
		},
		Email: email,
		Name:  name,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// RegistrationClaims contains the account_id for a one-time registration token
type RegistrationClaims struct {
	jwt.RegisteredClaims
	AccountID string `json:"account_id"`
	TokenType string `json:"token_type"`
}

// GenerateRegistrationToken creates a short-lived JWT that authorises registration under a specific account
func GenerateRegistrationToken(accountID, secret string, expiry time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("JWT secret cannot be empty")
	}

	now := time.Now()
	claims := RegistrationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
		},
		AccountID: accountID,
		TokenType: "registration",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateRegistrationToken validates a registration token and returns its claims
func ValidateRegistrationToken(tokenString, secret string) (*RegistrationClaims, error) {
	if secret == "" {
		return nil, fmt.Errorf("JWT secret cannot be empty")
	}

	token, err := jwt.ParseWithClaims(tokenString, &RegistrationClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*RegistrationClaims); ok && token.Valid {
		if claims.TokenType != "registration" {
			return nil, fmt.Errorf("invalid token type")
		}
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
