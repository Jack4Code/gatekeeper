package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log/slog"
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
	// Check if bootstrap admin email is configured
	adminEmail := service.config.BootstrapAdminEmail
	if adminEmail == "" {
		slog.Info("BOOTSTRAP_ADMIN_EMAIL not set, skipping admin bootstrap")
		return nil
	}

	adminAccountID := service.config.BootstrapAdminAccountID

	// Check if admin user already exists within the configured account
	existingUser, _ := service.userRepo.GetByEmail(adminAccountID, adminEmail)
	if existingUser != nil {
		slog.Info("admin user already exists, skipping bootstrap", "email", adminEmail)
		return nil
	}

	// Get password from config
	adminPassword := service.config.BootstrapAdminPassword
	if adminPassword == "" {
		slog.Info("BOOTSTRAP_ADMIN_PASSWORD not set, skipping admin bootstrap",
			"hint", "set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD to create an admin user")
		return nil
	}

	adminName := service.config.BootstrapAdminName
	if adminName == "" {
		adminName = "Admin"
	}

	slog.Info("creating bootstrap admin user", "email", adminEmail, "account_id", adminAccountID)

	// Hash password
	passwordHash, err := bedrock.HashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create admin user
	user, err := service.userRepo.Create(adminAccountID, adminEmail, passwordHash, adminName)
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

	slog.Info("bootstrap admin user created", "email", adminEmail)
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

	// Get account ID
	fmt.Print("Enter account ID (X-Account-ID) for admin user [leave empty for none]: ")
	adminAccountID, _ := reader.ReadString('\n')
	adminAccountID = strings.TrimSpace(adminAccountID)

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
	user, err := service.userRepo.Create(adminAccountID, adminEmail, passwordHash, adminName)
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
	fmt.Printf("Account ID: %q\n", adminAccountID)
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
