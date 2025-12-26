package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Jack4Code/bedrock"
	"github.com/Jack4Code/bedrock/config"
	"github.com/Jack4Code/gatekeeper/models"
	_ "github.com/lib/pq"
)

type AuthService struct {
	db                 *sql.DB
	userRepo           *models.UserRepository
	roleRepo           *models.RoleRepository
	permissionRepo     *models.PermissionRepository
	userRoleRepo       *models.UserRoleRepository
	rolePermissionRepo *models.RolePermissionRepository
	config             Config
}

type Config struct {
	Bedrock config.BaseConfig `toml:"bedrock"`

	JWTSecret      string        `toml:"jwt_secret" env:"JWT_SECRET"`
	JWTExpiration  time.Duration `toml:"jwt_expiration" env:"JWT_EXPIRATION"`
	DatabaseURL    string        `toml:"database_url" env:"DATABASE_URL"`
	MinPasswordLen int           `toml:"min_password_len" env:"MIN_PASSWORD_LEN"`

	// Bootstrap admin settings
	BootstrapAdminEmail    string `toml:"bootstrap_admin_email" env:"BOOTSTRAP_ADMIN_EMAIL"`
	BootstrapAdminPassword string `toml:"bootstrap_admin_password" env:"BOOTSTRAP_ADMIN_PASSWORD"`
	BootstrapAdminName     string `toml:"bootstrap_admin_name" env:"BOOTSTRAP_ADMIN_NAME"`
}

// Request/Response types
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UpdateUserRequest struct {
	Name string `json:"name"`
}

type AuthResponse struct {
	Token string       `json:"token"`
	User  *models.User `json:"user"`
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
		userRepo:           models.NewUserRepository(db),
		roleRepo:           models.NewRoleRepository(db),
		permissionRepo:     models.NewPermissionRepository(db),
		userRoleRepo:       models.NewUserRoleRepository(db),
		rolePermissionRepo: models.NewRolePermissionRepository(db),
		config:             cfg,
	}, nil
}

func (s *AuthService) OnStart(ctx context.Context) error {
	log.Println("Gatekeeper starting...")
	log.Println("Database connection established")

	// Bootstrap admin user if configured
	if err := BootstrapAdmin(s); err != nil {
		log.Printf("Warning: Bootstrap admin failed: %v", err)
	}

	return nil
}

func (s *AuthService) OnStop(ctx context.Context) error {
	log.Println("Gatekeeper stopping...")
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
		// Public routes
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

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, r *http.Request) bedrock.Response {
	var req RegisterRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	// Validate input
	if err := s.validateRegisterRequest(&req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": err.Error(),
		})
	}

	// Check if user already exists
	existingUser, _ := s.userRepo.GetByEmail(req.Email)
	if existingUser != nil {
		return bedrock.JSON(409, map[string]string{
			"error": "email already registered",
		})
	}

	// Hash password
	passwordHash, err := bedrock.HashPassword(req.Password)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to create account",
		})
	}

	// Create user
	user, err := s.userRepo.Create(req.Email, passwordHash, req.Name)
	if err != nil {
		if err == models.ErrEmailAlreadyExists {
			return bedrock.JSON(409, map[string]string{
				"error": "email already registered",
			})
		}
		log.Printf("Failed to create user: %v", err)
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
			log.Printf("Warning: Failed to assign default role to user: %v", err)
		}
	} else {
		log.Printf("Warning: Default 'user' role not found: %v", err)
	}

	// Get user roles and permissions for JWT
	roles, permissions := s.getUserRolesAndPermissions(user.ID)

	// Generate JWT with roles and permissions
	token, err := GenerateJWTWithRoles(user.ID, user.Email, roles, permissions, s.config.JWTSecret, s.config.JWTExpiration)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to generate token",
		})
	}

	return bedrock.JSON(201, AuthResponse{
		Token: token,
		User:  user,
	})
}

// Login authenticates a user
func (s *AuthService) Login(ctx context.Context, r *http.Request) bedrock.Response {
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

	// Get user by email
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		if err == models.ErrUserNotFound {
			return bedrock.JSON(401, map[string]string{
				"error": "invalid credentials",
			})
		}
		log.Printf("Database error during login: %v", err)
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

	// Get user roles and permissions for JWT
	roles, permissions := s.getUserRolesAndPermissions(user.ID)

	// Generate JWT with roles and permissions
	token, err := GenerateJWTWithRoles(user.ID, user.Email, roles, permissions, s.config.JWTSecret, s.config.JWTExpiration)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "login failed",
		})
	}

	return bedrock.JSON(200, AuthResponse{
		Token: token,
		User:  user,
	})
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
		log.Printf("Database error: %v", err)
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
		log.Printf("Database error: %v", err)
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
		log.Printf("Database error: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to delete user",
		})
	}

	return bedrock.JSON(200, map[string]string{
		"message": "account deleted successfully",
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
		log.Printf("Warning: Failed to get user roles: %v", err)
		return roleNames, permissionStrings
	}

	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	// Get user permissions (flattened from all roles)
	permissions, err := s.userRoleRepo.GetUserPermissions(userID)
	if err != nil {
		log.Printf("Warning: Failed to get user permissions: %v", err)
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

func main() {
	// Load configuration from config.toml with environment variable overrides
	var cfg Config
	loader := config.NewLoader("./config.toml")
	if err := loader.Load(&cfg); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Loaded config: %+v", cfg)
	log.Printf("Env JWT_SECRET=%q DATABASE_URL=%q", os.Getenv("JWT_SECRET"), os.Getenv("DATABASE_URL"))

	// Also decode TOML into a raw map to inspect what keys are present
	var raw map[string]interface{}
	if _, err := toml.DecodeFile("./config.toml", &raw); err != nil {
		log.Printf("toml decode failed: %v", err)
	} else {
		log.Printf("TOML raw keys: %+v", raw)
	}

	// Set defaults for app-specific config
	if cfg.JWTExpiration == 0 {
		cfg.JWTExpiration = 24 * time.Hour
	}
	if cfg.MinPasswordLen == 0 {
		cfg.MinPasswordLen = 8
	}
	if cfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	// Create service
	service, err := NewAuthService(cfg)
	if err != nil {
		log.Fatalf("Failed to create gatekeeper: %v", err)
	}

	// Run server with bedrock config
	if err := bedrock.Run(service, cfg.Bedrock); err != nil {
		log.Fatal(err)
	}
}
