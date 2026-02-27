package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"time"

	axiomslog "github.com/axiomhq/axiom-go/adapters/slog"
	"github.com/Jack4Code/bedrock"
	migrate "github.com/Jack4Code/bedrock-migrate/pkg/commands"
	"github.com/Jack4Code/bedrock/config"
	"github.com/Jack4Code/gatekeeper/models"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
)

type AuthService struct {
	db                 *sql.DB
	accountRepo        *models.AccountRepository
	userRepo           *models.UserRepository
	roleRepo           *models.RoleRepository
	permissionRepo     *models.PermissionRepository
	userRoleRepo       *models.UserRoleRepository
	rolePermissionRepo *models.RolePermissionRepository
	refreshTokenRepo   *models.RefreshTokenRepository
	config             Config
}

type Config struct {
	Bedrock config.BaseConfig `toml:"bedrock"`

	JWTSecret              string        `toml:"jwt_secret" env:"JWT_SECRET"`
	JWTExpiration          time.Duration `toml:"jwt_expiration" env:"JWT_EXPIRATION"`
	IDTokenExpiration      time.Duration `toml:"id_token_expiration" env:"ID_TOKEN_EXPIRATION"`
	RefreshTokenExpiration time.Duration `toml:"refresh_token_expiration" env:"REFRESH_TOKEN_EXPIRATION"`
	DatabaseURL            string        `toml:"database_url" env:"DATABASE_URL"`
	MinPasswordLen         int           `toml:"min_password_len" env:"MIN_PASSWORD_LEN"`

	// Bootstrap admin settings
	BootstrapAdminEmail     string `toml:"bootstrap_admin_email" env:"BOOTSTRAP_ADMIN_EMAIL"`
	BootstrapAdminPassword  string `toml:"bootstrap_admin_password" env:"BOOTSTRAP_ADMIN_PASSWORD"`
	BootstrapAdminName      string `toml:"bootstrap_admin_name" env:"BOOTSTRAP_ADMIN_NAME"`
	BootstrapAdminAccountID string `toml:"bootstrap_admin_account_id" env:"BOOTSTRAP_ADMIN_ACCOUNT_ID"`

	// Registration token lifetime (short-lived tokens that gate self-registration)
	RegistrationTokenExpiration time.Duration `toml:"registration_token_expiration" env:"REGISTRATION_TOKEN_EXPIRATION"`
}

// Request/Response types
type RegisterRequest struct {
	RegistrationToken string `json:"registration_token"`
	Email             string `json:"email"`
	Password          string `json:"password"`
	Name              string `json:"name"`
}

type RegistrationTokenResponse struct {
	RegistrationToken string    `json:"registration_token"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type SignupRequest struct {
	AccountName string `json:"account_name"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Name        string `json:"name"`
}

type SignupResponse struct {
	Token        string          `json:"token"`
	IDToken      string          `json:"id_token"`
	RefreshToken string          `json:"refresh_token"`
	User         *models.User    `json:"user"`
	Account      *models.Account `json:"account"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UpdateUserRequest struct {
	Name string `json:"name"`
}

type AuthResponse struct {
	Token        string       `json:"token"`
	IDToken      string       `json:"id_token"`
	RefreshToken string       `json:"refresh_token"`
	User         *models.User `json:"user"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func NewAuthService(cfg Config) (*AuthService, error) {
	// Connect to database
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &AuthService{
		db:                 db,
		accountRepo:        models.NewAccountRepository(db),
		userRepo:           models.NewUserRepository(db),
		roleRepo:           models.NewRoleRepository(db),
		permissionRepo:     models.NewPermissionRepository(db),
		userRoleRepo:       models.NewUserRoleRepository(db),
		rolePermissionRepo: models.NewRolePermissionRepository(db),
		refreshTokenRepo:   models.NewRefreshTokenRepository(db),
		config:             cfg,
	}, nil
}

func (s *AuthService) OnStart(ctx context.Context) error {
	slog.Info("gatekeeper starting")
	slog.Info("database connection established")

	// Bootstrap admin user if configured
	if err := BootstrapAdmin(s); err != nil {
		slog.Warn("bootstrap admin failed", "error", err)
	}

	return nil
}

func (s *AuthService) OnStop(ctx context.Context) error {
	slog.Info("gatekeeper stopping")
	if s.db != nil {
		s.db.Close()
	}
	return nil
}

func (s *AuthService) Routes() []bedrock.Route {
	// Create auth middleware that includes roles and permissions
	authMiddleware := RequireAuthWithRoles(s.config.JWTSecret)

	// Admin-only middleware (requires admin role)
	adminMiddleware := RequireRole("admin")

	return []bedrock.Route{
		// Human-readable status page
		{
			Method:  "GET",
			Path:    "/status",
			Handler: s.Health,
		},

		// Terminal login UI
		{
			Method:  "GET",
			Path:    "/login",
			Handler: s.LoginPage,
		},

		// Terminal register UI
		{
			Method:  "GET",
			Path:    "/register",
			Handler: s.RegisterPage,
		},

		// Public routes
		{
			Method:  "POST",
			Path:    "/api/signup",
			Handler: s.Signup,
		},
		{
			Method:  "POST",
			Path:    "/api/register",
			Handler: s.Register,
		},
		{
			Method:  "POST",
			Path:    "/api/login",
			Handler: s.Login,
		},
		{
			Method:  "POST",
			Path:    "/api/refresh",
			Handler: s.Refresh,
		},
		{
			Method:  "POST",
			Path:    "/api/logout",
			Handler: s.Logout,
		},

		// Protected routes (require authentication)
		{
			Method:     "GET",
			Path:       "/api/users/me",
			Handler:    s.GetCurrentUser,
			Middleware: []bedrock.Middleware{authMiddleware},
		},
		{
			Method:     "PUT",
			Path:       "/api/users/me",
			Handler:    s.UpdateCurrentUser,
			Middleware: []bedrock.Middleware{authMiddleware},
		},
		{
			Method:     "DELETE",
			Path:       "/api/users/me",
			Handler:    s.DeleteCurrentUser,
			Middleware: []bedrock.Middleware{authMiddleware},
		},

		// Registration token generation (admin only)
		{
			Method:     "POST",
			Path:       "/api/v1/registration-tokens",
			Handler:    s.CreateRegistrationToken,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},

		// Role management endpoints (admin only)
		{
			Method:     "POST",
			Path:       "/api/v1/roles",
			Handler:    s.CreateRole,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},
		{
			Method:     "GET",
			Path:       "/api/v1/roles",
			Handler:    s.ListRoles,
			Middleware: []bedrock.Middleware{authMiddleware},
		},
		{
			Method:     "GET",
			Path:       "/api/v1/roles/{id}",
			Handler:    s.GetRole,
			Middleware: []bedrock.Middleware{authMiddleware},
		},
		{
			Method:     "PUT",
			Path:       "/api/v1/roles/{id}",
			Handler:    s.UpdateRole,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},
		{
			Method:     "DELETE",
			Path:       "/api/v1/roles/{id}",
			Handler:    s.DeleteRole,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},

		// Permission management endpoints (admin only)
		{
			Method:     "POST",
			Path:       "/api/v1/permissions",
			Handler:    s.CreatePermission,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},
		{
			Method:     "GET",
			Path:       "/api/v1/permissions",
			Handler:    s.ListPermissions,
			Middleware: []bedrock.Middleware{authMiddleware},
		},
		{
			Method:     "GET",
			Path:       "/api/v1/permissions/{id}",
			Handler:    s.GetPermission,
			Middleware: []bedrock.Middleware{authMiddleware},
		},
		{
			Method:     "DELETE",
			Path:       "/api/v1/permissions/{id}",
			Handler:    s.DeletePermission,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},

		// User-role assignment endpoints (admin only)
		{
			Method:     "POST",
			Path:       "/api/v1/users/{id}/roles",
			Handler:    s.AssignRoleToUser,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},
		{
			Method:     "DELETE",
			Path:       "/api/v1/users/{id}/roles/{roleId}",
			Handler:    s.RemoveRoleFromUser,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},
		{
			Method:     "GET",
			Path:       "/api/v1/users/{id}/roles",
			Handler:    s.GetUserRoles,
			Middleware: []bedrock.Middleware{authMiddleware},
		},

		// Role-permission assignment endpoints (admin only)
		{
			Method:     "POST",
			Path:       "/api/v1/roles/{id}/permissions",
			Handler:    s.AssignPermissionToRole,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},
		{
			Method:     "POST",
			Path:       "/api/v1/roles/{id}/permissions/batch",
			Handler:    s.AssignMultiplePermissionsToRole,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},
		{
			Method:     "DELETE",
			Path:       "/api/v1/roles/{id}/permissions/{permissionId}",
			Handler:    s.RemovePermissionFromRole,
			Middleware: []bedrock.Middleware{authMiddleware, adminMiddleware},
		},
	}
}

// Signup creates a brand-new account and its first admin user in one step
func (s *AuthService) Signup(ctx context.Context, r *http.Request) bedrock.Response {
	var req SignupRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.AccountName == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "account_name is required",
		})
	}

	// Reuse the same field validation as regular registration
	regReq := &RegisterRequest{Email: req.Email, Password: req.Password, Name: req.Name}
	if err := s.validateRegisterRequest(regReq); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": err.Error(),
		})
	}

	// Create the account (unique name enforced by DB)
	account, err := s.accountRepo.Create(req.AccountName)
	if err != nil {
		if err == models.ErrAccountNameTaken {
			return bedrock.JSON(409, map[string]string{
				"error": "account name already taken",
			})
		}
		slog.Error("failed to create account", "op", "signup", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to create account",
		})
	}

	// Hash password
	passwordHash, err := bedrock.HashPassword(req.Password)
	if err != nil {
		slog.Error("failed to hash password", "op", "signup", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to create account",
		})
	}

	// Create the first user under this account
	user, err := s.userRepo.Create(account.ID, req.Email, passwordHash, req.Name)
	if err != nil {
		slog.Error("failed to create user", "op", "signup", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to create account",
		})
	}

	// Assign the admin role to the account owner
	adminRole, err := s.roleRepo.GetByName("admin")
	if err != nil {
		slog.Warn("admin role not found", "op", "signup", "error", err)
	} else {
		userRole := &models.UserRole{UserID: user.ID, RoleID: adminRole.ID}
		if err := s.userRoleRepo.Assign(userRole); err != nil {
			slog.Warn("failed to assign admin role", "op", "signup", "error", err)
		}
	}

	// Issue token pair
	tokenPair, err := s.issueTokenPair(user)
	if err != nil {
		slog.Error("failed to issue token pair", "op", "signup", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to generate token",
		})
	}

	return bedrock.JSON(201, SignupResponse{
		Token:        tokenPair.Token,
		IDToken:      tokenPair.IDToken,
		RefreshToken: tokenPair.RefreshToken,
		User:         tokenPair.User,
		Account:      account,
	})
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, r *http.Request) bedrock.Response {
	var req RegisterRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.RegistrationToken == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "registration_token is required",
		})
	}

	regClaims, err := ValidateRegistrationToken(req.RegistrationToken, s.config.JWTSecret)
	if err != nil {
		return bedrock.JSON(401, map[string]string{
			"error": "invalid or expired registration token",
		})
	}

	accountID := regClaims.AccountID

	// Validate input
	if err := s.validateRegisterRequest(&req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": err.Error(),
		})
	}

	// Check if user already exists within this account
	existingUser, _ := s.userRepo.GetByEmail(accountID, req.Email)
	if existingUser != nil {
		return bedrock.JSON(409, map[string]string{
			"error": "email already registered",
		})
	}

	// Hash password
	passwordHash, err := bedrock.HashPassword(req.Password)
	if err != nil {
		slog.Error("failed to hash password", "op", "register", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to create account",
		})
	}

	// Create user
	user, err := s.userRepo.Create(accountID, req.Email, passwordHash, req.Name)
	if err != nil {
		if err == models.ErrEmailAlreadyExists {
			return bedrock.JSON(409, map[string]string{
				"error": "email already registered",
			})
		}
		slog.Error("failed to create user", "op", "register", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to create account",
		})
	}

	// Assign default 'user' role to new users
	defaultRole, err := s.roleRepo.GetByName("user")
	if err == nil {
		userRole := &models.UserRole{
			UserID: user.ID,
			RoleID: defaultRole.ID,
		}
		if err := s.userRoleRepo.Assign(userRole); err != nil {
			slog.Warn("failed to assign default role", "op", "register", "user_id", user.ID, "error", err)
		}
	} else {
		slog.Warn("default user role not found", "op", "register", "error", err)
	}

	// Issue token pair (access + refresh)
	resp, err := s.issueTokenPair(user)
	if err != nil {
		slog.Error("failed to issue token pair", "op", "register", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to generate token",
		})
	}

	return bedrock.JSON(201, resp)
}

// isValidUUID returns true if s is a valid UUID
func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// Login authenticates a user
func (s *AuthService) Login(ctx context.Context, r *http.Request) bedrock.Response {
	accountID := r.Header.Get("X-Account-ID")
	if accountID == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "X-Account-ID header is required",
		})
	}
	if !isValidUUID(accountID) {
		return bedrock.JSON(400, map[string]string{
			"error": "X-Account-ID must be a valid UUID",
		})
	}

	var req LoginRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "email and password are required",
		})
	}

	// Get user by email within this account
	user, err := s.userRepo.GetByEmail(accountID, req.Email)
	if err != nil {
		if err == models.ErrUserNotFound {
			return bedrock.JSON(401, map[string]string{
				"error": "invalid credentials",
			})
		}
		slog.Error("database error during login", "account_id", accountID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "login failed",
		})
	}

	// Check password
	if err := bedrock.CheckPassword(req.Password, user.PasswordHash); err != nil {
		return bedrock.JSON(401, map[string]string{
			"error": "invalid credentials",
		})
	}

	// Issue token pair (access + refresh)
	resp, err := s.issueTokenPair(user)
	if err != nil {
		slog.Error("failed to issue token pair", "op", "login", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "login failed",
		})
	}

	return bedrock.JSON(200, resp)
}

// GetCurrentUser returns the authenticated user's information
func (s *AuthService) GetCurrentUser(ctx context.Context, r *http.Request) bedrock.Response {
	userID, ok := GetUserID(ctx)
	if !ok {
		return bedrock.JSON(500, map[string]string{
			"error": "user ID not found in context",
		})
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		if err == models.ErrUserNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "user not found",
			})
		}
		slog.Error("database error", "op", "get_current_user", "user_id", userID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to fetch user",
		})
	}

	return bedrock.JSON(200, user)
}

// UpdateCurrentUser updates the authenticated user's information
func (s *AuthService) UpdateCurrentUser(ctx context.Context, r *http.Request) bedrock.Response {
	userID, ok := GetUserID(ctx)
	if !ok {
		return bedrock.JSON(500, map[string]string{
			"error": "user ID not found in context",
		})
	}

	var req UpdateUserRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	// Validate
	if req.Name == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "name is required",
		})
	}

	// Update user
	user, err := s.userRepo.Update(userID, req.Name)
	if err != nil {
		if err == models.ErrUserNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "user not found",
			})
		}
		slog.Error("database error", "op", "update_current_user", "user_id", userID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to update user",
		})
	}

	return bedrock.JSON(200, user)
}

// DeleteCurrentUser deletes the authenticated user's account
func (s *AuthService) DeleteCurrentUser(ctx context.Context, r *http.Request) bedrock.Response {
	userID, ok := GetUserID(ctx)
	if !ok {
		return bedrock.JSON(500, map[string]string{
			"error": "user ID not found in context",
		})
	}

	err := s.userRepo.Delete(userID)
	if err != nil {
		if err == models.ErrUserNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "user not found",
			})
		}
		slog.Error("database error", "op", "delete_current_user", "user_id", userID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to delete user",
		})
	}

	return bedrock.JSON(200, map[string]string{
		"message": "account deleted successfully",
	})
}

// CreateRegistrationToken generates a short-lived token that allows a new user to register under the caller's account
func (s *AuthService) CreateRegistrationToken(ctx context.Context, r *http.Request) bedrock.Response {
	accountID, ok := GetAccountID(ctx)
	if !ok {
		return bedrock.JSON(500, map[string]string{
			"error": "account ID not found in context",
		})
	}

	expiry := s.config.RegistrationTokenExpiration
	token, err := GenerateRegistrationToken(accountID, s.config.JWTSecret, expiry)
	if err != nil {
		slog.Error("failed to generate registration token", "account_id", accountID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to generate registration token",
		})
	}

	return bedrock.JSON(200, RegistrationTokenResponse{
		RegistrationToken: token,
		ExpiresAt:         time.Now().Add(expiry),
	})
}

// issueTokenPair generates an access JWT and an opaque refresh token, storing the refresh token hash in the DB.
func (s *AuthService) issueTokenPair(user *models.User) (*AuthResponse, error) {
	// Get user roles and permissions for JWT
	roles, permissions := s.getUserRolesAndPermissions(user.ID)

	// Generate access JWT
	accessToken, err := GenerateJWTWithRoles(user.ID, user.AccountID, user.Email, roles, permissions, s.config.JWTSecret, s.config.JWTExpiration)
	if err != nil {
		return nil, err
	}

	// Generate ID token
	idToken, err := GenerateIDToken(user.ID, user.Email, user.Name, s.config.JWTSecret, s.config.IDTokenExpiration)
	if err != nil {
		return nil, err
	}

	// Generate opaque refresh token
	plaintext, hash, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Store refresh token hash in DB with a new family
	familyID := uuid.New().String()
	expiresAt := time.Now().Add(s.config.RefreshTokenExpiration)
	_, err = s.refreshTokenRepo.Create(user.ID, hash, familyID, expiresAt)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		Token:        accessToken,
		IDToken:      idToken,
		RefreshToken: plaintext,
		User:         user,
	}, nil
}

// Refresh validates a refresh token, rotates it, and returns a new token pair
func (s *AuthService) Refresh(ctx context.Context, r *http.Request) bedrock.Response {
	var req RefreshRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.RefreshToken == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "refresh_token is required",
		})
	}

	// Look up the token by its hash
	tokenHash := sha256Hex(req.RefreshToken)
	storedToken, err := s.refreshTokenRepo.GetByTokenHash(tokenHash)
	if err != nil {
		if err == models.ErrRefreshTokenNotFound {
			return bedrock.JSON(401, map[string]string{
				"error": "invalid refresh token",
			})
		}
		slog.Error("database error during refresh", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "refresh failed",
		})
	}

	// Reuse detection: if the token has been revoked, revoke the entire family
	if storedToken.Revoked {
		slog.Warn("refresh token reuse detected, revoking family", "family_id", storedToken.FamilyID)
		if err := s.refreshTokenRepo.RevokeFamily(storedToken.FamilyID); err != nil {
			slog.Error("failed to revoke token family", "family_id", storedToken.FamilyID, "error", err)
		}
		return bedrock.JSON(401, map[string]string{
			"error": "refresh token reuse detected, all sessions in this family have been revoked",
		})
	}

	// Check expiration
	if time.Now().After(storedToken.ExpiresAt) {
		return bedrock.JSON(401, map[string]string{
			"error": "refresh token expired",
		})
	}

	// Get the user
	user, err := s.userRepo.GetByID(storedToken.UserID)
	if err != nil {
		slog.Error("user not found during refresh", "user_id", storedToken.UserID, "error", err)
		return bedrock.JSON(401, map[string]string{
			"error": "user not found",
		})
	}

	// Get user roles and permissions for new JWT
	roles, permissions := s.getUserRolesAndPermissions(user.ID)

	// Generate new access JWT
	accessToken, err := GenerateJWTWithRoles(user.ID, user.AccountID, user.Email, roles, permissions, s.config.JWTSecret, s.config.JWTExpiration)
	if err != nil {
		slog.Error("failed to generate JWT during refresh", "user_id", user.ID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "refresh failed",
		})
	}

	// Generate new ID token
	idToken, err := GenerateIDToken(user.ID, user.Email, user.Name, s.config.JWTSecret, s.config.IDTokenExpiration)
	if err != nil {
		slog.Error("failed to generate ID token during refresh", "user_id", user.ID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "refresh failed",
		})
	}

	// Generate new refresh token in the same family
	newPlaintext, newHash, err := GenerateRefreshToken()
	if err != nil {
		slog.Error("failed to generate refresh token", "user_id", user.ID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "refresh failed",
		})
	}

	expiresAt := time.Now().Add(s.config.RefreshTokenExpiration)
	newToken, err := s.refreshTokenRepo.Create(user.ID, newHash, storedToken.FamilyID, expiresAt)
	if err != nil {
		slog.Error("failed to store new refresh token", "user_id", user.ID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "refresh failed",
		})
	}

	// Revoke the old token and link to the new one
	if err := s.refreshTokenRepo.RevokeByID(storedToken.ID, newToken.ID); err != nil {
		slog.Error("failed to revoke old refresh token", "token_id", storedToken.ID, "error", err)
	}

	return bedrock.JSON(200, AuthResponse{
		Token:        accessToken,
		IDToken:      idToken,
		RefreshToken: newPlaintext,
		User:         user,
	})
}

// Logout revokes the refresh token family
func (s *AuthService) Logout(ctx context.Context, r *http.Request) bedrock.Response {
	var req LogoutRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.RefreshToken == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "refresh_token is required",
		})
	}

	// Look up the token by its hash
	tokenHash := sha256Hex(req.RefreshToken)
	storedToken, err := s.refreshTokenRepo.GetByTokenHash(tokenHash)
	if err != nil {
		if err == models.ErrRefreshTokenNotFound {
			// Token not found — treat as success (idempotent logout)
			return bedrock.JSON(200, map[string]string{
				"message": "logged out successfully",
			})
		}
		slog.Error("database error during logout", "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "logout failed",
		})
	}

	// Revoke the entire token family
	if err := s.refreshTokenRepo.RevokeFamily(storedToken.FamilyID); err != nil {
		slog.Error("failed to revoke token family during logout", "family_id", storedToken.FamilyID, "error", err)
		return bedrock.JSON(500, map[string]string{
			"error": "logout failed",
		})
	}

	return bedrock.JSON(200, map[string]string{
		"message": "logged out successfully",
	})
}

// Helper functions

// getUserRolesAndPermissions fetches and formats user roles and permissions for JWT
func (s *AuthService) getUserRolesAndPermissions(userID string) ([]string, []string) {
	var roleNames []string
	var permissionStrings []string

	// Get user roles
	roles, err := s.userRoleRepo.GetUserRoles(userID)
	if err != nil {
		slog.Warn("failed to get user roles", "user_id", userID, "error", err)
		return roleNames, permissionStrings
	}

	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	// Get user permissions (flattened from all roles)
	permissions, err := s.userRoleRepo.GetUserPermissions(userID)
	if err != nil {
		slog.Warn("failed to get user permissions", "user_id", userID, "error", err)
		return roleNames, permissionStrings
	}

	for _, perm := range permissions {
		permissionStrings = append(permissionStrings, models.FormatPermission(perm.Resource, perm.Action))
	}

	return roleNames, permissionStrings
}

// Validation helpers

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func (s *AuthService) validateRegisterRequest(req *RegisterRequest) error {
	if req.Email == "" {
		return errors.New("email is required")
	}
	if !emailRegex.MatchString(req.Email) {
		return errors.New("invalid email format")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	if len(req.Password) < s.config.MinPasswordLen {
		return errors.New("password must be at least 8 characters")
	}
	if req.Name == "" {
		return errors.New("name is required")
	}
	return nil
}

// multiHandler fans out log records to multiple slog.Handler implementations.
type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: handlers}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: handlers}
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "gatekeeper",
		Short: "Gatekeeper Authentication Service",
		Long:  "Gatekeeper is a modern authentication and authorization service with RBAC support",
		Run: func(cmd *cobra.Command, args []string) {
			// Default to serve if no subcommand is provided
			serveCommand(cmd, args)
		},
	}

	// Add serve subcommand
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Gatekeeper service",
		Long:  "Start the Gatekeeper HTTP service with authentication and RBAC endpoints",
		Run:   serveCommand,
	}
	rootCmd.AddCommand(serveCmd)

	// Add migrate subcommand with all bedrock-migrate commands
	rootCmd.AddCommand(migrate.MigrateCommand())

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func serveCommand(cmd *cobra.Command, args []string) {
	// Initialize structured JSON logging to stdout
	stdoutHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	handlers := []slog.Handler{stdoutHandler}

	// Add Axiom handler if configured
	if os.Getenv("AXIOM_TOKEN") != "" {
		axiomHandler, err := axiomslog.New()
		if err != nil {
			slog.New(stdoutHandler).Warn("failed to initialize Axiom logger", "error", err)
		} else {
			defer axiomHandler.Close()
			handlers = append(handlers, axiomHandler)
		}
	}

	if len(handlers) == 1 {
		slog.SetDefault(slog.New(stdoutHandler))
	} else {
		slog.SetDefault(slog.New(&multiHandler{handlers: handlers}))
	}

	// Load configuration from config.toml with environment variable overrides
	var cfg Config
	loader := config.NewLoader("./config.toml")
	if err := loader.Load(&cfg); err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Set defaults for app-specific config
	if cfg.JWTExpiration == 0 {
		cfg.JWTExpiration = 24 * time.Hour
	}
	if cfg.IDTokenExpiration == 0 {
		cfg.IDTokenExpiration = cfg.JWTExpiration
	}
	if cfg.RefreshTokenExpiration == 0 {
		cfg.RefreshTokenExpiration = 7 * 24 * time.Hour
	}
	if cfg.RegistrationTokenExpiration == 0 {
		cfg.RegistrationTokenExpiration = 1 * time.Hour
	}
	if cfg.MinPasswordLen == 0 {
		cfg.MinPasswordLen = 8
	}
	if cfg.JWTSecret == "" {
		slog.Error("JWT_SECRET environment variable is required")
		os.Exit(1)
	}
	if cfg.DatabaseURL == "" {
		slog.Error("DATABASE_URL environment variable is required")
		os.Exit(1)
	}

	// Create service
	service, err := NewAuthService(cfg)
	if err != nil {
		slog.Error("failed to create gatekeeper", "error", err)
		os.Exit(1)
	}

	// Run server with bedrock config
	if err := bedrock.Run(service, cfg.Bedrock); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
