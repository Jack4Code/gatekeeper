package models

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRoleNotFound         = errors.New("role not found")
	ErrRoleNameAlreadyExists = errors.New("role name already exists")
)

// Role represents a role in the RBAC system
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleRepository handles database operations for roles
type RoleRepository struct {
	db *sql.DB
}

// NewRoleRepository creates a new RoleRepository
func NewRoleRepository(db *sql.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// Create creates a new role
func (r *RoleRepository) Create(role *Role) error {
	role.ID = uuid.New().String()
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()

	query := `
		INSERT INTO roles (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRow(query, role.ID, role.Name, role.Description, role.CreatedAt, role.UpdatedAt).
		Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)

	if err != nil {
		if isDuplicateKeyError(err, "roles_name_key") {
			return ErrRoleNameAlreadyExists
		}
		return err
	}

	return nil
}

// GetByID retrieves a role by ID
func (r *RoleRepository) GetByID(id string) (*Role, error) {
	role := &Role{}
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE id = $1
	`

	err := r.db.QueryRow(query, id).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrRoleNotFound
	}
	if err != nil {
		return nil, err
	}

	return role, nil
}

// GetByName retrieves a role by name
func (r *RoleRepository) GetByName(name string) (*Role, error) {
	role := &Role{}
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE name = $1
	`

	err := r.db.QueryRow(query, name).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrRoleNotFound
	}
	if err != nil {
		return nil, err
	}

	return role, nil
}

// Update updates a role
func (r *RoleRepository) Update(role *Role) error {
	role.UpdatedAt = time.Now()

	query := `
		UPDATE roles
		SET name = $1, description = $2, updated_at = $3
		WHERE id = $4
		RETURNING updated_at
	`

	err := r.db.QueryRow(query, role.Name, role.Description, role.UpdatedAt, role.ID).
		Scan(&role.UpdatedAt)

	if err == sql.ErrNoRows {
		return ErrRoleNotFound
	}
	if err != nil {
		if isDuplicateKeyError(err, "roles_name_key") {
			return ErrRoleNameAlreadyExists
		}
		return err
	}

	return nil
}

// Delete deletes a role
func (r *RoleRepository) Delete(id string) error {
	query := `DELETE FROM roles WHERE id = $1`
	result, err := r.db.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRoleNotFound
	}

	return nil
}

// List retrieves all roles with optional pagination
func (r *RoleRepository) List(limit, offset int) ([]*Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		ORDER BY name
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		role := &Role{}
		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, rows.Err()
}

// GetPermissions retrieves all permissions for a role
func (r *RoleRepository) GetPermissions(roleID string) ([]*Permission, error) {
	query := `
		SELECT p.id, p.resource, p.action, p.description, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.resource, p.action
	`

	rows, err := r.db.Query(query, roleID)
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
