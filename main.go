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

	"github.com/Jack4Code/bedrock"
	"github.com/Jack4Code/gatekeeper/models"
	_ "github.com/lib/pq"
)

type AuthService struct {
	db       *sql.DB
	userRepo *models.UserRepository
	config   Config
}

type Config struct {
	JWTSecret      string
	JWTExpiration  time.Duration
	DatabaseURL    string
	MinPasswordLen int
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
		db:       db,
		userRepo: models.NewUserRepository(db),
		config:   cfg,
	}, nil
}

func (s *AuthService) OnStart(ctx context.Context) error {
	log.Println("Gatekeeper starting...")
	log.Println("Database connection established")
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
	// Create auth middleware
	authMiddleware := bedrock.RequireAuth(s.config.JWTSecret)

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

	// Generate JWT
	token, err := bedrock.GenerateJWT(user.ID, s.config.JWTSecret, s.config.JWTExpiration)
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

	// Generate JWT
	token, err := bedrock.GenerateJWT(user.ID, s.config.JWTSecret, s.config.JWTExpiration)
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
	userID, ok := bedrock.GetUserID(ctx)
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
	userID, ok := bedrock.GetUserID(ctx)
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
	userID, ok := bedrock.GetUserID(ctx)
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
	// Load Bedrock config
	bedrockCfg := bedrock.LoadConfig()

	// Load auth service config from environment
	authCfg := Config{
		JWTSecret:      getEnv("JWT_SECRET", ""),
		JWTExpiration:  24 * time.Hour,
		DatabaseURL:    getEnv("DATABASE_URL", ""),
		MinPasswordLen: 8,
	}

	// Validate required config
	if authCfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}
	if authCfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	// Create service
	service, err := NewAuthService(authCfg)
	if err != nil {
		log.Fatalf("Failed to create gatekeeper: %v", err)
	}

	// Run server
	if err := bedrock.Run(service, bedrockCfg); err != nil {
		log.Fatal(err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
