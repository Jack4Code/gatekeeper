package models

import (
	"database/sql"
	"errors"
	"time"
)

var (
	ErrUserRoleNotFound      = errors.New("user role assignment not found")
	ErrUserRoleAlreadyExists = errors.New("user already has this role")
)

// UserRole represents the assignment of a role to a user
type UserRole struct {
	UserID     string    `json:"user_id"`
	RoleID     string    `json:"role_id"`
	AssignedAt time.Time `json:"assigned_at"`
	AssignedBy string    `json:"assigned_by,omitempty"` // ID of the user who assigned this role
}

// UserRoleRepository handles database operations for user-role assignments
type UserRoleRepository struct {
	db *sql.DB
}

// NewUserRoleRepository creates a new UserRoleRepository
func NewUserRoleRepository(db *sql.DB) *UserRoleRepository {
	return &UserRoleRepository{db: db}
}

// Assign assigns a role to a user
func (ur *UserRoleRepository) Assign(userRole *UserRole) error {
	userRole.AssignedAt = time.Now()

	query := `
		INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
		VALUES ($1, $2, $3, $4)
		RETURNING assigned_at
	`

	var assignedBy interface{}
	if userRole.AssignedBy != "" {
		assignedBy = userRole.AssignedBy
	}

	err := ur.db.QueryRow(query, userRole.UserID, userRole.RoleID, userRole.AssignedAt, assignedBy).
		Scan(&userRole.AssignedAt)

	if err != nil {
		if isDuplicateKeyError(err, "user_roles_pkey") {
			return ErrUserRoleAlreadyExists
		}
		return err
	}

	return nil
}

// Remove removes a role from a user
func (ur *UserRoleRepository) Remove(userID, roleID string) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`
	result, err := ur.db.Exec(query, userID, roleID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrUserRoleNotFound
	}

	return nil
}

// GetUserRoles retrieves all roles assigned to a user
func (ur *UserRoleRepository) GetUserRoles(userID string) ([]*Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.name
	`

	rows, err := ur.db.Query(query, userID)
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

// GetUserPermissions retrieves all permissions for a user (flattened from all their roles)
func (ur *UserRoleRepository) GetUserPermissions(userID string) ([]*Permission, error) {
	query := `
		SELECT DISTINCT p.id, p.resource, p.action, p.description, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY p.resource, p.action
	`

	rows, err := ur.db.Query(query, userID)
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

// HasRole checks if a user has a specific role
func (ur *UserRoleRepository) HasRole(userID, roleID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM user_roles
			WHERE user_id = $1 AND role_id = $2
		)
	`

	var exists bool
	err := ur.db.QueryRow(query, userID, roleID).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// HasPermission checks if a user has a specific permission (via any of their roles)
func (ur *UserRoleRepository) HasPermission(userID, resource, action string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM permissions p
			INNER JOIN role_permissions rp ON p.id = rp.permission_id
			INNER JOIN user_roles ur ON rp.role_id = ur.role_id
			WHERE ur.user_id = $1 AND p.resource = $2 AND p.action = $3
		)
	`

	var exists bool
	err := ur.db.QueryRow(query, userID, resource, action).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// GetUsersWithRole retrieves all users who have a specific role
func (ur *UserRoleRepository) GetUsersWithRole(roleID string) ([]*User, error) {
	query := `
		SELECT u.id, u.email, u.name, u.created_at, u.updated_at
		FROM users u
		INNER JOIN user_roles ur ON u.id = ur.user_id
		WHERE ur.role_id = $1
		ORDER BY u.email
	`

	rows, err := ur.db.Query(query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

// RemoveAllUserRoles removes all role assignments for a user
func (ur *UserRoleRepository) RemoveAllUserRoles(userID string) error {
	query := `DELETE FROM user_roles WHERE user_id = $1`
	_, err := ur.db.Exec(query, userID)
	return err
}

// RemoveAllRoleAssignments removes all user assignments for a role
func (ur *UserRoleRepository) RemoveAllRoleAssignments(roleID string) error {
	query := `DELETE FROM user_roles WHERE role_id = $1`
	_, err := ur.db.Exec(query, roleID)
	return err
}
