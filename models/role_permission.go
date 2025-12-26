package models

import (
	"database/sql"
	"errors"
)

var (
	ErrRolePermissionNotFound      = errors.New("role permission assignment not found")
	ErrRolePermissionAlreadyExists = errors.New("role already has this permission")
)

// RolePermission represents the assignment of a permission to a role
type RolePermission struct {
	RoleID       string `json:"role_id"`
	PermissionID string `json:"permission_id"`
}

// RolePermissionRepository handles database operations for role-permission assignments
type RolePermissionRepository struct {
	db *sql.DB
}

// NewRolePermissionRepository creates a new RolePermissionRepository
func NewRolePermissionRepository(db *sql.DB) *RolePermissionRepository {
	return &RolePermissionRepository{db: db}
}

// Assign assigns a permission to a role
func (rp *RolePermissionRepository) Assign(rolePermission *RolePermission) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1, $2)
	`

	_, err := rp.db.Exec(query, rolePermission.RoleID, rolePermission.PermissionID)
	if err != nil {
		if isDuplicateKeyError(err, "role_permissions_pkey") {
			return ErrRolePermissionAlreadyExists
		}
		return err
	}

	return nil
}

// Remove removes a permission from a role
func (rp *RolePermissionRepository) Remove(roleID, permissionID string) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`
	result, err := rp.db.Exec(query, roleID, permissionID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRolePermissionNotFound
	}

	return nil
}

// GetRolePermissions retrieves all permissions for a role
func (rp *RolePermissionRepository) GetRolePermissions(roleID string) ([]*Permission, error) {
	query := `
		SELECT p.id, p.resource, p.action, p.description, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.resource, p.action
	`

	rows, err := rp.db.Query(query, roleID)
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

// GetPermissionRoles retrieves all roles that have a specific permission
func (rp *RolePermissionRepository) GetPermissionRoles(permissionID string) ([]*Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		INNER JOIN role_permissions rp ON r.id = rp.role_id
		WHERE rp.permission_id = $1
		ORDER BY r.name
	`

	rows, err := rp.db.Query(query, permissionID)
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

// HasPermission checks if a role has a specific permission
func (rp *RolePermissionRepository) HasPermission(roleID, permissionID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM role_permissions
			WHERE role_id = $1 AND permission_id = $2
		)
	`

	var exists bool
	err := rp.db.QueryRow(query, roleID, permissionID).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// RemoveAllRolePermissions removes all permission assignments for a role
func (rp *RolePermissionRepository) RemoveAllRolePermissions(roleID string) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1`
	_, err := rp.db.Exec(query, roleID)
	return err
}

// RemoveAllPermissionAssignments removes all role assignments for a permission
func (rp *RolePermissionRepository) RemoveAllPermissionAssignments(permissionID string) error {
	query := `DELETE FROM role_permissions WHERE permission_id = $1`
	_, err := rp.db.Exec(query, permissionID)
	return err
}

// AssignMultiple assigns multiple permissions to a role in a single transaction
func (rp *RolePermissionRepository) AssignMultiple(roleID string, permissionIDs []string) error {
	if len(permissionIDs) == 0 {
		return nil
	}

	tx, err := rp.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, permissionID := range permissionIDs {
		_, err = stmt.Exec(roleID, permissionID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
