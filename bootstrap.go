package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Jack4Code/bedrock"
	"github.com/Jack4Code/gatekeeper/models"
	_ "github.com/lib/pq"
	"golang.org/x/term"
)

// BootstrapAdmin creates an initial admin user if none exists
func BootstrapAdmin(service *AuthService) error {
	// Check if BOOTSTRAP_ADMIN_EMAIL environment variable is set
	adminEmail := os.Getenv("BOOTSTRAP_ADMIN_EMAIL")
	if adminEmail == "" {
		log.Println("BOOTSTRAP_ADMIN_EMAIL not set, skipping admin bootstrap")
		return nil
	}

	// Check if admin user already exists
	existingUser, _ := service.userRepo.GetByEmail(adminEmail)
	if existingUser != nil {
		log.Printf("Admin user %s already exists, skipping bootstrap", adminEmail)
		return nil
	}

	// Get password from environment or prompt
	adminPassword := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if adminPassword == "" {
		log.Println("BOOTSTRAP_ADMIN_PASSWORD not set, skipping admin bootstrap")
		log.Println("To create an admin user, set both BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD environment variables")
		return nil
	}

	adminName := os.Getenv("BOOTSTRAP_ADMIN_NAME")
	if adminName == "" {
		adminName = "Admin"
	}

	log.Printf("Creating bootstrap admin user: %s", adminEmail)

	// Hash password
	passwordHash, err := bedrock.HashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create admin user
	user, err := service.userRepo.Create(adminEmail, passwordHash, adminName)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	// Get admin role
	adminRole, err := service.roleRepo.GetByName("admin")
	if err != nil {
		return fmt.Errorf("failed to get admin role: %w", err)
	}

	// Assign admin role to user
	userRole := &models.UserRole{
		UserID: user.ID,
		RoleID: adminRole.ID,
	}
	if err := service.userRoleRepo.Assign(userRole); err != nil {
		return fmt.Errorf("failed to assign admin role: %w", err)
	}

	log.Printf("✓ Bootstrap admin user created successfully: %s", adminEmail)
	return nil
}

// InteractiveBootstrap runs an interactive bootstrap setup
func InteractiveBootstrap() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== Gatekeeper Admin Bootstrap ===")
	fmt.Println()

	// Get database URL
	fmt.Print("Enter DATABASE_URL [postgres://localhost/gatekeeper]: ")
	databaseURL, _ := reader.ReadString('\n')
	databaseURL = strings.TrimSpace(databaseURL)
	if databaseURL == "" {
		databaseURL = "postgres://localhost/gatekeeper"
	}

	// Get JWT secret
	fmt.Print("Enter JWT_SECRET [will generate random if empty]: ")
	jwtSecret, _ := reader.ReadString('\n')
	jwtSecret = strings.TrimSpace(jwtSecret)
	if jwtSecret == "" {
		jwtSecret = generateRandomSecret()
		fmt.Printf("Generated JWT_SECRET: %s\n", jwtSecret)
	}

	// Get admin email
	fmt.Print("Enter admin email: ")
	adminEmail, _ := reader.ReadString('\n')
	adminEmail = strings.TrimSpace(adminEmail)
	if adminEmail == "" {
		return fmt.Errorf("admin email is required")
	}

	// Get admin password
	fmt.Print("Enter admin password: ")
	adminPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	adminPassword := string(adminPasswordBytes)
	fmt.Println()

	if len(adminPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	// Get admin name
	fmt.Print("Enter admin name [Admin]: ")
	adminName, _ := reader.ReadString('\n')
	adminName = strings.TrimSpace(adminName)
	if adminName == "" {
		adminName = "Admin"
	}

	fmt.Println()
	fmt.Println("Creating admin user...")

	// Connect to database
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create service
	cfg := Config{
		JWTSecret:      jwtSecret,
		JWTExpiration:  24 * time.Hour,
		DatabaseURL:    databaseURL,
		MinPasswordLen: 8,
	}

	service := &AuthService{
		db:                 db,
		userRepo:           models.NewUserRepository(db),
		roleRepo:           models.NewRoleRepository(db),
		permissionRepo:     models.NewPermissionRepository(db),
		userRoleRepo:       models.NewUserRoleRepository(db),
		rolePermissionRepo: models.NewRolePermissionRepository(db),
		config:             cfg,
	}

	// Hash password
	passwordHash, err := bedrock.HashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create admin user
	user, err := service.userRepo.Create(adminEmail, passwordHash, adminName)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	// Get admin role
	adminRole, err := service.roleRepo.GetByName("admin")
	if err != nil {
		return fmt.Errorf("failed to get admin role (did you run migrations?): %w", err)
	}

	// Assign admin role to user
	userRole := &models.UserRole{
		UserID: user.ID,
		RoleID: adminRole.ID,
	}
	if err := service.userRoleRepo.Assign(userRole); err != nil {
		return fmt.Errorf("failed to assign admin role: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Admin user created successfully!")
	fmt.Printf("Email: %s\n", adminEmail)
	fmt.Printf("Role: admin\n")
	fmt.Println()
	fmt.Println("Add these to your .env file:")
	fmt.Printf("DATABASE_URL=%s\n", databaseURL)
	fmt.Printf("JWT_SECRET=%s\n", jwtSecret)

	return nil
}

func generateRandomSecret() string {
	// Simple random secret generation
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), "change-me-in-production")
}
