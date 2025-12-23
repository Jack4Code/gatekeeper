package main

import (
	"context"
	"log"
	"net/http"
	"strconv"

	"github.com/Jack4Code/bedrock"
	"github.com/Jack4Code/gatekeeper/models"
	"github.com/gorilla/mux"
)

// Request/Response types for RBAC

type CreateRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type UpdateRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type CreatePermissionRequest struct {
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type AssignRoleRequest struct {
	RoleID string `json:"role_id"`
}

type AssignPermissionRequest struct {
	PermissionID string `json:"permission_id"`
}

type AssignMultiplePermissionsRequest struct {
	PermissionIDs []string `json:"permission_ids"`
}

type RoleWithPermissions struct {
	*models.Role
	Permissions []*models.Permission `json:"permissions"`
}

type UserRolesResponse struct {
	Roles       []*models.Role       `json:"roles"`
	Permissions []*models.Permission `json:"permissions"`
}

// Role Handlers

// CreateRole creates a new role (admin only)
func (s *AuthService) CreateRole(ctx context.Context, r *http.Request) bedrock.Response {
	var req CreateRoleRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.Name == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "role name is required",
		})
	}

	role := &models.Role{
		Name:        req.Name,
		Description: req.Description,
	}

	if err := s.roleRepo.Create(role); err != nil {
		if err == models.ErrRoleNameAlreadyExists {
			return bedrock.JSON(409, map[string]string{
				"error": "role name already exists",
			})
		}
		log.Printf("Failed to create role: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to create role",
		})
	}

	return bedrock.JSON(201, role)
}

// ListRoles lists all roles
func (s *AuthService) ListRoles(ctx context.Context, r *http.Request) bedrock.Response {
	limit := 100
	offset := 0

	// Parse query parameters
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	roles, err := s.roleRepo.List(limit, offset)
	if err != nil {
		log.Printf("Failed to list roles: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to list roles",
		})
	}

	return bedrock.JSON(200, map[string]interface{}{
		"roles":  roles,
		"limit":  limit,
		"offset": offset,
	})
}

// GetRole retrieves a role by ID including its permissions
func (s *AuthService) GetRole(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	roleID := vars["id"]

	role, err := s.roleRepo.GetByID(roleID)
	if err != nil {
		if err == models.ErrRoleNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "role not found",
			})
		}
		log.Printf("Failed to get role: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to get role",
		})
	}

	permissions, err := s.roleRepo.GetPermissions(roleID)
	if err != nil {
		log.Printf("Failed to get role permissions: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to get role permissions",
		})
	}

	return bedrock.JSON(200, RoleWithPermissions{
		Role:        role,
		Permissions: permissions,
	})
}

// UpdateRole updates a role
func (s *AuthService) UpdateRole(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	roleID := vars["id"]

	var req UpdateRoleRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.Name == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "role name is required",
		})
	}

	role := &models.Role{
		ID:          roleID,
		Name:        req.Name,
		Description: req.Description,
	}

	if err := s.roleRepo.Update(role); err != nil {
		if err == models.ErrRoleNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "role not found",
			})
		}
		if err == models.ErrRoleNameAlreadyExists {
			return bedrock.JSON(409, map[string]string{
				"error": "role name already exists",
			})
		}
		log.Printf("Failed to update role: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to update role",
		})
	}

	return bedrock.JSON(200, role)
}

// DeleteRole deletes a role
func (s *AuthService) DeleteRole(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	roleID := vars["id"]

	if err := s.roleRepo.Delete(roleID); err != nil {
		if err == models.ErrRoleNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "role not found",
			})
		}
		log.Printf("Failed to delete role: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to delete role",
		})
	}

	return bedrock.JSON(200, map[string]string{
		"message": "role deleted successfully",
	})
}

// Permission Handlers

// CreatePermission creates a new permission (admin only)
func (s *AuthService) CreatePermission(ctx context.Context, r *http.Request) bedrock.Response {
	var req CreatePermissionRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.Resource == "" || req.Action == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "resource and action are required",
		})
	}

	permission := &models.Permission{
		Resource:    req.Resource,
		Action:      req.Action,
		Description: req.Description,
	}

	if err := s.permissionRepo.Create(permission); err != nil {
		if err == models.ErrPermissionAlreadyExists {
			return bedrock.JSON(409, map[string]string{
				"error": "permission already exists",
			})
		}
		if err == models.ErrInvalidPermissionFormat {
			return bedrock.JSON(400, map[string]string{
				"error": err.Error(),
			})
		}
		log.Printf("Failed to create permission: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to create permission",
		})
	}

	return bedrock.JSON(201, permission)
}

// ListPermissions lists all permissions
func (s *AuthService) ListPermissions(ctx context.Context, r *http.Request) bedrock.Response {
	limit := 100
	offset := 0

	// Parse query parameters
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	resource := r.URL.Query().Get("resource")

	var permissions []*models.Permission
	var err error

	if resource != "" {
		permissions, err = s.permissionRepo.ListByResource(resource, limit, offset)
	} else {
		permissions, err = s.permissionRepo.List(limit, offset)
	}

	if err != nil {
		log.Printf("Failed to list permissions: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to list permissions",
		})
	}

	return bedrock.JSON(200, map[string]interface{}{
		"permissions": permissions,
		"limit":       limit,
		"offset":      offset,
	})
}

// GetPermission retrieves a permission by ID
func (s *AuthService) GetPermission(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	permissionID := vars["id"]

	permission, err := s.permissionRepo.GetByID(permissionID)
	if err != nil {
		if err == models.ErrPermissionNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "permission not found",
			})
		}
		log.Printf("Failed to get permission: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to get permission",
		})
	}

	return bedrock.JSON(200, permission)
}

// DeletePermission deletes a permission
func (s *AuthService) DeletePermission(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	permissionID := vars["id"]

	if err := s.permissionRepo.Delete(permissionID); err != nil {
		if err == models.ErrPermissionNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "permission not found",
			})
		}
		log.Printf("Failed to delete permission: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to delete permission",
		})
	}

	return bedrock.JSON(200, map[string]string{
		"message": "permission deleted successfully",
	})
}

// User-Role Assignment Handlers

// AssignRoleToUser assigns a role to a user (admin only)
func (s *AuthService) AssignRoleToUser(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	userID := vars["id"]

	var req AssignRoleRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.RoleID == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "role_id is required",
		})
	}

	// Get the ID of the user performing the assignment
	assignedBy, _ := bedrock.GetUserID(ctx)

	userRole := &models.UserRole{
		UserID:     userID,
		RoleID:     req.RoleID,
		AssignedBy: assignedBy,
	}

	if err := s.userRoleRepo.Assign(userRole); err != nil {
		if err == models.ErrUserRoleAlreadyExists {
			return bedrock.JSON(409, map[string]string{
				"error": "user already has this role",
			})
		}
		log.Printf("Failed to assign role to user: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to assign role",
		})
	}

	return bedrock.JSON(201, userRole)
}

// RemoveRoleFromUser removes a role from a user (admin only)
func (s *AuthService) RemoveRoleFromUser(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	userID := vars["id"]
	roleID := vars["roleId"]

	if err := s.userRoleRepo.Remove(userID, roleID); err != nil {
		if err == models.ErrUserRoleNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "user does not have this role",
			})
		}
		log.Printf("Failed to remove role from user: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to remove role",
		})
	}

	return bedrock.JSON(200, map[string]string{
		"message": "role removed successfully",
	})
}

// GetUserRoles retrieves all roles and permissions for a user
func (s *AuthService) GetUserRoles(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	userID := vars["id"]

	roles, err := s.userRoleRepo.GetUserRoles(userID)
	if err != nil {
		log.Printf("Failed to get user roles: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to get user roles",
		})
	}

	permissions, err := s.userRoleRepo.GetUserPermissions(userID)
	if err != nil {
		log.Printf("Failed to get user permissions: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to get user permissions",
		})
	}

	return bedrock.JSON(200, UserRolesResponse{
		Roles:       roles,
		Permissions: permissions,
	})
}

// Role-Permission Assignment Handlers

// AssignPermissionToRole assigns a permission to a role (admin only)
func (s *AuthService) AssignPermissionToRole(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	roleID := vars["id"]

	var req AssignPermissionRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.PermissionID == "" {
		return bedrock.JSON(400, map[string]string{
			"error": "permission_id is required",
		})
	}

	rolePermission := &models.RolePermission{
		RoleID:       roleID,
		PermissionID: req.PermissionID,
	}

	if err := s.rolePermissionRepo.Assign(rolePermission); err != nil {
		if err == models.ErrRolePermissionAlreadyExists {
			return bedrock.JSON(409, map[string]string{
				"error": "role already has this permission",
			})
		}
		log.Printf("Failed to assign permission to role: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to assign permission",
		})
	}

	return bedrock.JSON(201, rolePermission)
}

// AssignMultiplePermissionsToRole assigns multiple permissions to a role (admin only)
func (s *AuthService) AssignMultiplePermissionsToRole(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	roleID := vars["id"]

	var req AssignMultiplePermissionsRequest
	if err := bedrock.DecodeJSON(r, &req); err != nil {
		return bedrock.JSON(400, map[string]string{
			"error": "invalid request body",
		})
	}

	if len(req.PermissionIDs) == 0 {
		return bedrock.JSON(400, map[string]string{
			"error": "permission_ids array is required and cannot be empty",
		})
	}

	if err := s.rolePermissionRepo.AssignMultiple(roleID, req.PermissionIDs); err != nil {
		log.Printf("Failed to assign permissions to role: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to assign permissions",
		})
	}

	return bedrock.JSON(201, map[string]string{
		"message": "permissions assigned successfully",
	})
}

// RemovePermissionFromRole removes a permission from a role (admin only)
func (s *AuthService) RemovePermissionFromRole(ctx context.Context, r *http.Request) bedrock.Response {
	vars := mux.Vars(r)
	roleID := vars["id"]
	permissionID := vars["permissionId"]

	if err := s.rolePermissionRepo.Remove(roleID, permissionID); err != nil {
		if err == models.ErrRolePermissionNotFound {
			return bedrock.JSON(404, map[string]string{
				"error": "role does not have this permission",
			})
		}
		log.Printf("Failed to remove permission from role: %v", err)
		return bedrock.JSON(500, map[string]string{
			"error": "failed to remove permission",
		})
	}

	return bedrock.JSON(200, map[string]string{
		"message": "permission removed successfully",
	})
}
