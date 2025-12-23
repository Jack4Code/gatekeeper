package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/Jack4Code/bedrock"
)

// Context keys for storing authorization data
type contextKey string

const (
	contextKeyUserID      contextKey = "user_id"
	contextKeyRoles       contextKey = "roles"
	contextKeyPermissions contextKey = "permissions"
	contextKeyEmail       contextKey = "email"
)

// RequireAuthWithRoles is a middleware that validates JWT and extracts roles/permissions
func RequireAuthWithRoles(secret string) bedrock.Middleware {
	return func(next bedrock.Handler) bedrock.Handler {
		return func(ctx context.Context, r *http.Request) bedrock.Response {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				return bedrock.JSON(401, map[string]string{
					"error": "missing authorization header",
				})
			}

			// Check for Bearer token format
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return bedrock.JSON(401, map[string]string{
					"error": "invalid authorization header format",
				})
			}

			tokenString := parts[1]

			// Validate token and extract claims
			claims, err := ValidateJWTWithRoles(tokenString, secret)
			if err != nil {
				return bedrock.JSON(401, map[string]string{
					"error": "invalid or expired token",
				})
			}

			// Add user data to context
			ctx = context.WithValue(ctx, contextKeyUserID, claims.UserID)
			ctx = context.WithValue(ctx, contextKeyEmail, claims.Email)
			ctx = context.WithValue(ctx, contextKeyRoles, claims.Roles)
			ctx = context.WithValue(ctx, contextKeyPermissions, claims.Permissions)

			return next(ctx, r)
		}
	}
}

// GetUserID retrieves user ID from context
func GetUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(contextKeyUserID).(string)
	return userID, ok
}

// GetRoles retrieves roles from context
func GetRoles(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(contextKeyRoles).([]string)
	return roles, ok
}

// GetPermissions retrieves permissions from context
func GetPermissions(ctx context.Context) ([]string, bool) {
	permissions, ok := ctx.Value(contextKeyPermissions).([]string)
	return permissions, ok
}

// GetEmail retrieves email from context
func GetEmail(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(contextKeyEmail).(string)
	return email, ok
}

// RequirePermission returns a middleware that checks for a specific permission
func RequirePermission(permission string) bedrock.Middleware {
	return func(next bedrock.Handler) bedrock.Handler {
		return func(ctx context.Context, r *http.Request) bedrock.Response {
			permissions, ok := GetPermissions(ctx)
			if !ok {
				return bedrock.JSON(403, map[string]string{
					"error": "no permissions found in token",
				})
			}

			if !contains(permissions, permission) {
				return bedrock.JSON(403, map[string]string{
					"error":      "insufficient permissions",
					"required":   permission,
				})
			}

			return next(ctx, r)
		}
	}
}

// RequireAnyPermission returns a middleware that checks for any of the specified permissions
func RequireAnyPermission(requiredPermissions ...string) bedrock.Middleware {
	return func(next bedrock.Handler) bedrock.Handler {
		return func(ctx context.Context, r *http.Request) bedrock.Response {
			permissions, ok := GetPermissions(ctx)
			if !ok {
				return bedrock.JSON(403, map[string]string{
					"error": "no permissions found in token",
				})
			}

			for _, required := range requiredPermissions {
				if contains(permissions, required) {
					return next(ctx, r)
				}
			}

			return bedrock.JSON(403, map[string]string{
				"error":      "insufficient permissions",
				"required_any": strings.Join(requiredPermissions, ", "),
			})
		}
	}
}

// RequireAllPermissions returns a middleware that checks for all specified permissions
func RequireAllPermissions(requiredPermissions ...string) bedrock.Middleware {
	return func(next bedrock.Handler) bedrock.Handler {
		return func(ctx context.Context, r *http.Request) bedrock.Response {
			permissions, ok := GetPermissions(ctx)
			if !ok {
				return bedrock.JSON(403, map[string]string{
					"error": "no permissions found in token",
				})
			}

			for _, required := range requiredPermissions {
				if !contains(permissions, required) {
					return bedrock.JSON(403, map[string]string{
						"error":        "insufficient permissions",
						"required_all": strings.Join(requiredPermissions, ", "),
					})
				}
			}

			return next(ctx, r)
		}
	}
}

// RequireRole returns a middleware that checks for a specific role
func RequireRole(role string) bedrock.Middleware {
	return func(next bedrock.Handler) bedrock.Handler {
		return func(ctx context.Context, r *http.Request) bedrock.Response {
			roles, ok := GetRoles(ctx)
			if !ok {
				return bedrock.JSON(403, map[string]string{
					"error": "no roles found in token",
				})
			}

			if !contains(roles, role) {
				return bedrock.JSON(403, map[string]string{
					"error":    "insufficient permissions",
					"required": role,
				})
			}

			return next(ctx, r)
		}
	}
}

// RequireAnyRole returns a middleware that checks for any of the specified roles
func RequireAnyRole(requiredRoles ...string) bedrock.Middleware {
	return func(next bedrock.Handler) bedrock.Handler {
		return func(ctx context.Context, r *http.Request) bedrock.Response {
			roles, ok := GetRoles(ctx)
			if !ok {
				return bedrock.JSON(403, map[string]string{
					"error": "no roles found in token",
				})
			}

			for _, required := range requiredRoles {
				if contains(roles, required) {
					return next(ctx, r)
				}
			}

			return bedrock.JSON(403, map[string]string{
				"error":        "insufficient permissions",
				"required_any": strings.Join(requiredRoles, ", "),
			})
		}
	}
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
