-- migrations/002_create_rbac_tables.sql
-- Create RBAC (Role-Based Access Control) tables

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create permissions table
-- Permissions follow the "resource:action" naming convention
-- Examples: users:read, users:write, roles:read, roles:write
CREATE TABLE IF NOT EXISTS permissions (
    id VARCHAR(36) PRIMARY KEY,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(resource, action)
);

-- Create user_roles junction table (many-to-many: users <-> roles)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by VARCHAR(36),
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Create role_permissions junction table (many-to-many: roles <-> permissions)
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id VARCHAR(36) NOT NULL,
    permission_id VARCHAR(36) NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

-- Create updated_at trigger for roles table
CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default roles
INSERT INTO roles (id, name, description, created_at, updated_at)
VALUES
    (
        'role-admin-default',
        'admin',
        'Administrator with full system access',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        'role-user-default',
        'user',
        'Standard user with basic permissions',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    )
ON CONFLICT (name) DO NOTHING;

-- Insert default permissions
INSERT INTO permissions (id, resource, action, description, created_at)
VALUES
    -- User permissions
    ('perm-users-read', 'users', 'read', 'View user information', CURRENT_TIMESTAMP),
    ('perm-users-write', 'users', 'write', 'Create and update users', CURRENT_TIMESTAMP),
    ('perm-users-delete', 'users', 'delete', 'Delete users', CURRENT_TIMESTAMP),

    -- Role permissions
    ('perm-roles-read', 'roles', 'read', 'View roles', CURRENT_TIMESTAMP),
    ('perm-roles-write', 'roles', 'write', 'Create and update roles', CURRENT_TIMESTAMP),
    ('perm-roles-delete', 'roles', 'delete', 'Delete roles', CURRENT_TIMESTAMP),

    -- Permission permissions
    ('perm-permissions-read', 'permissions', 'read', 'View permissions', CURRENT_TIMESTAMP),
    ('perm-permissions-write', 'permissions', 'write', 'Create permissions', CURRENT_TIMESTAMP),
    ('perm-permissions-delete', 'permissions', 'delete', 'Delete permissions', CURRENT_TIMESTAMP),

    -- User-role assignment permissions
    ('perm-user-roles-read', 'user-roles', 'read', 'View user role assignments', CURRENT_TIMESTAMP),
    ('perm-user-roles-write', 'user-roles', 'write', 'Assign and remove user roles', CURRENT_TIMESTAMP)
ON CONFLICT (resource, action) DO NOTHING;

-- Assign all permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    'role-admin-default',
    id
FROM permissions
ON CONFLICT DO NOTHING;

-- Assign basic permissions to user role
INSERT INTO role_permissions (role_id, permission_id)
VALUES
    ('role-user-default', 'perm-users-read'),
    ('role-user-default', 'perm-roles-read'),
    ('role-user-default', 'perm-permissions-read')
ON CONFLICT DO NOTHING;
