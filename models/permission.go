package models

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrPermissionNotFound         = errors.New("permission not found")
	ErrPermissionAlreadyExists    = errors.New("permission already exists")
	ErrInvalidPermissionFormat    = errors.New("invalid permission format, expected 'resource:action'")
)

// Permission represents a permission in the RBAC system
type Permission struct {
	ID          string    `json:"id"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// PermissionRepository handles database operations for permissions
type PermissionRepository struct {
	db *sql.DB
}

// NewPermissionRepository creates a new PermissionRepository
func NewPermissionRepository(db *sql.DB) *PermissionRepository {
	return &PermissionRepository{db: db}
}

// ValidatePermissionFormat validates that resource:action format is correct
func ValidatePermissionFormat(resource, action string) error {
	if resource == "" || action == "" {
		return ErrInvalidPermissionFormat
	}

	// Ensure no colons in resource or action to prevent parsing issues
	if strings.Contains(resource, ":") || strings.Contains(action, ":") {
		return ErrInvalidPermissionFormat
	}

	return nil
}

// FormatPermission formats resource and action as "resource:action"
func FormatPermission(resource, action string) string {
	return fmt.Sprintf("%s:%s", resource, action)
}

// ParsePermission parses "resource:action" string into components
func ParsePermission(permission string) (resource, action string, err error) {
	parts := strings.Split(permission, ":")
	if len(parts) != 2 {
		return "", "", ErrInvalidPermissionFormat
	}
	return parts[0], parts[1], nil
}

// Create creates a new permission
func (p *PermissionRepository) Create(permission *Permission) error {
	if err := ValidatePermissionFormat(permission.Resource, permission.Action); err != nil {
		return err
	}

	permission.ID = uuid.New().String()
	permission.CreatedAt = time.Now()

	query := `
		INSERT INTO permissions (id, resource, action, description, created_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at
	`

	err := p.db.QueryRow(query, permission.ID, permission.Resource, permission.Action, permission.Description, permission.CreatedAt).
		Scan(&permission.ID, &permission.CreatedAt)

	if err != nil {
		if isDuplicateKeyError(err, "permissions_resource_action_key") {
			return ErrPermissionAlreadyExists
		}
		return err
	}

	return nil
}

// GetByID retrieves a permission by ID
func (p *PermissionRepository) GetByID(id string) (*Permission, error) {
	permission := &Permission{}
	query := `
		SELECT id, resource, action, description, created_at
		FROM permissions
		WHERE id = $1
	`

	err := p.db.QueryRow(query, id).Scan(
		&permission.ID,
		&permission.Resource,
		&permission.Action,
		&permission.Description,
		&permission.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrPermissionNotFound
	}
	if err != nil {
		return nil, err
	}

	return permission, nil
}

// GetByResourceAction retrieves a permission by resource and action
func (p *PermissionRepository) GetByResourceAction(resource, action string) (*Permission, error) {
	permission := &Permission{}
	query := `
		SELECT id, resource, action, description, created_at
		FROM permissions
		WHERE resource = $1 AND action = $2
	`

	err := p.db.QueryRow(query, resource, action).Scan(
		&permission.ID,
		&permission.Resource,
		&permission.Action,
		&permission.Description,
		&permission.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrPermissionNotFound
	}
	if err != nil {
		return nil, err
	}

	return permission, nil
}

// Delete deletes a permission
func (p *PermissionRepository) Delete(id string) error {
	query := `DELETE FROM permissions WHERE id = $1`
	result, err := p.db.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrPermissionNotFound
	}

	return nil
}

// List retrieves all permissions with optional pagination
func (p *PermissionRepository) List(limit, offset int) ([]*Permission, error) {
	query := `
		SELECT id, resource, action, description, created_at
		FROM permissions
		ORDER BY resource, action
		LIMIT $1 OFFSET $2
	`

	rows, err := p.db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		permission := &Permission{}
		err := rows.Scan(
			&permission.ID,
			&permission.Resource,
			&permission.Action,
			&permission.Description,
			&permission.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, rows.Err()
}

// ListByResource retrieves all permissions for a specific resource
func (p *PermissionRepository) ListByResource(resource string, limit, offset int) ([]*Permission, error) {
	query := `
		SELECT id, resource, action, description, created_at
		FROM permissions
		WHERE resource = $1
		ORDER BY action
		LIMIT $2 OFFSET $3
	`

	rows, err := p.db.Query(query, resource, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		permission := &Permission{}
		err := rows.Scan(
			&permission.ID,
			&permission.Resource,
			&permission.Action,
			&permission.Description,
			&permission.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, rows.Err()
}
