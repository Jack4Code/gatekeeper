# Gatekeeper

An authentication service built with [Bedrock](https://github.com/Jack4Code/bedrock) and PostgreSQL.

## Features

- ✅ User registration with email/password
- ✅ User login with JWT token generation
- ✅ Protected routes with JWT validation
- ✅ User profile management (get, update, delete)
- ✅ **Role-Based Access Control (RBAC)**
  - ✅ Flexible role and permission system
  - ✅ Many-to-many user-role relationships
  - ✅ Many-to-many role-permission relationships
  - ✅ JWT enrichment with roles and permissions
  - ✅ Middleware for permission and role checking
  - ✅ Default 'admin' and 'user' roles
  - ✅ Permission naming convention: `resource:action`
- ✅ PostgreSQL database with proper schema
- ✅ Input validation (email format, password length)
- ✅ Secure password hashing with bcrypt
- ✅ Repository pattern for clean database access
- ✅ Graceful shutdown
- ✅ Health checks for orchestration (Kubernetes/Nomad)
- ✅ Bootstrap admin user functionality

## Tech Stack

- **Framework**: Bedrock (custom Go framework)
- **Database**: PostgreSQL
- **Auth**: JWT (JSON Web Tokens)
- **Password Hashing**: bcrypt
- **Database Driver**: lib/pq

## Project Structure

```
gatekeeper/
├── main.go                           # Main application & auth handlers
├── handlers_rbac.go                  # RBAC endpoint handlers
├── middleware.go                     # Authorization middleware
├── jwt.go                            # JWT generation with roles/permissions
├── bootstrap.go                      # Admin user bootstrap
├── models/
│   ├── user.go                       # User model & repository
│   ├── role.go                       # Role model & repository
│   ├── permission.go                 # Permission model & repository
│   ├── user_role.go                  # User-role assignment model & repository
│   ├── role_permission.go            # Role-permission assignment model & repository
│   └── helpers.go                    # Shared helper functions
├── migrations/
│   ├── 001_create_users_table.sql    # User schema
│   └── 002_create_rbac_tables.sql    # RBAC schema with seed data
├── config.toml                       # Bedrock configuration
├── .env.example                      # Environment variables template
├── go.mod                            # Dependencies
└── README.md                         # This file
```

## Quick Start

### 1. Prerequisites

- Go 1.25+
- PostgreSQL 12+

### 2. Setup Database

```bash
# Create database
createdb authdb

# Create user
psql -d authdb
CREATE USER authuser WITH PASSWORD 'authpass';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
\q

# Run migrations (in order)
psql -d authdb -U authuser -f migrations/001_create_users_table.sql
psql -d authdb -U authuser -f migrations/002_create_rbac_tables.sql
```

### 3. Configure Environment

```bash
# Copy example env file
cp .env.example .env

# Edit .env and set:
# - JWT_SECRET (use a strong random string, 32+ characters recommended)
# - DATABASE_URL (your postgres connection string)
# - BOOTSTRAP_ADMIN_EMAIL (optional, email for initial admin user)
# - BOOTSTRAP_ADMIN_PASSWORD (optional, password for initial admin user)
# - BOOTSTRAP_ADMIN_NAME (optional, name for initial admin user)
```

Example .env:
```bash
JWT_SECRET=your-super-secret-jwt-key-min-32-chars
DATABASE_URL=postgres://authuser:authpass@localhost/authdb?sslmode=disable
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=secureadminpass123
BOOTSTRAP_ADMIN_NAME=Administrator
```

### 4. Install Dependencies

```bash
go mod tidy
```

### 5. Run the Service

```bash
# Load environment variables
export $(cat .env | xargs)

# Run
go run main.go
```

The service will start on:
- **HTTP**: http://localhost:8080
- **Health**: http://localhost:9090

**Note**: If you configured `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`, an admin user will be automatically created on first startup.

## API Endpoints

### Public Endpoints

#### Register
```bash
POST /api/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123",
  "name": "John Doe"
}

Response (201):
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "John Doe",
    "created_at": "2024-12-17T10:30:00Z",
    "updated_at": "2024-12-17T10:30:00Z"
  }
}
```

#### Login
```bash
POST /api/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}

Response (200):
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "John Doe",
    "created_at": "2024-12-17T10:30:00Z",
    "updated_at": "2024-12-17T10:30:00Z"
  }
}
```

### Protected Endpoints

All protected endpoints require the JWT token in the Authorization header:
```
Authorization: Bearer <token>
```

#### Get Current User
```bash
GET /api/users/me
Authorization: Bearer <token>

Response (200):
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "name": "John Doe",
  "created_at": "2024-12-17T10:30:00Z",
  "updated_at": "2024-12-17T10:30:00Z"
}
```

#### Update Current User
```bash
PUT /api/users/me
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Jane Doe"
}

Response (200):
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "name": "Jane Doe",
  "created_at": "2024-12-17T10:30:00Z",
  "updated_at": "2024-12-17T10:30:00Z"
}
```

#### Delete Current User
```bash
DELETE /api/users/me
Authorization: Bearer <token>

Response (200):
{
  "message": "account deleted successfully"
}
```

### RBAC Endpoints

All RBAC endpoints require authentication. Most require admin role.

#### Role Management

##### Create Role (Admin Only)
```bash
POST /api/v1/roles
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "name": "moderator",
  "description": "Moderator with limited admin capabilities"
}

Response (201):
{
  "id": "role-uuid",
  "name": "moderator",
  "description": "Moderator with limited admin capabilities",
  "created_at": "2024-12-17T10:30:00Z",
  "updated_at": "2024-12-17T10:30:00Z"
}
```

##### List All Roles
```bash
GET /api/v1/roles?limit=100&offset=0
Authorization: Bearer <token>

Response (200):
{
  "roles": [
    {
      "id": "role-admin-default",
      "name": "admin",
      "description": "Administrator with full system access",
      "created_at": "2024-12-17T10:30:00Z",
      "updated_at": "2024-12-17T10:30:00Z"
    },
    {
      "id": "role-user-default",
      "name": "user",
      "description": "Standard user with basic permissions",
      "created_at": "2024-12-17T10:30:00Z",
      "updated_at": "2024-12-17T10:30:00Z"
    }
  ],
  "limit": 100,
  "offset": 0
}
```

##### Get Role Details (Including Permissions)
```bash
GET /api/v1/roles/{roleId}
Authorization: Bearer <token>

Response (200):
{
  "id": "role-admin-default",
  "name": "admin",
  "description": "Administrator with full system access",
  "created_at": "2024-12-17T10:30:00Z",
  "updated_at": "2024-12-17T10:30:00Z",
  "permissions": [
    {
      "id": "perm-users-read",
      "resource": "users",
      "action": "read",
      "description": "View user information",
      "created_at": "2024-12-17T10:30:00Z"
    },
    {
      "id": "perm-users-write",
      "resource": "users",
      "action": "write",
      "description": "Create and update users",
      "created_at": "2024-12-17T10:30:00Z"
    }
  ]
}
```

##### Update Role (Admin Only)
```bash
PUT /api/v1/roles/{roleId}
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "name": "moderator",
  "description": "Updated description"
}

Response (200):
{
  "id": "role-uuid",
  "name": "moderator",
  "description": "Updated description",
  "created_at": "2024-12-17T10:30:00Z",
  "updated_at": "2024-12-17T10:35:00Z"
}
```

##### Delete Role (Admin Only)
```bash
DELETE /api/v1/roles/{roleId}
Authorization: Bearer <admin-token>

Response (200):
{
  "message": "role deleted successfully"
}
```

#### Permission Management

##### Create Permission (Admin Only)
```bash
POST /api/v1/permissions
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "resource": "posts",
  "action": "delete",
  "description": "Delete posts"
}

Response (201):
{
  "id": "perm-uuid",
  "resource": "posts",
  "action": "delete",
  "description": "Delete posts",
  "created_at": "2024-12-17T10:30:00Z"
}
```

##### List All Permissions
```bash
GET /api/v1/permissions?limit=100&offset=0&resource=users
Authorization: Bearer <token>

Response (200):
{
  "permissions": [
    {
      "id": "perm-users-read",
      "resource": "users",
      "action": "read",
      "description": "View user information",
      "created_at": "2024-12-17T10:30:00Z"
    }
  ],
  "limit": 100,
  "offset": 0
}
```

##### Get Permission
```bash
GET /api/v1/permissions/{permissionId}
Authorization: Bearer <token>

Response (200):
{
  "id": "perm-users-read",
  "resource": "users",
  "action": "read",
  "description": "View user information",
  "created_at": "2024-12-17T10:30:00Z"
}
```

##### Delete Permission (Admin Only)
```bash
DELETE /api/v1/permissions/{permissionId}
Authorization: Bearer <admin-token>

Response (200):
{
  "message": "permission deleted successfully"
}
```

#### User-Role Assignments

##### Assign Role to User (Admin Only)
```bash
POST /api/v1/users/{userId}/roles
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "role_id": "role-uuid"
}

Response (201):
{
  "user_id": "user-uuid",
  "role_id": "role-uuid",
  "assigned_at": "2024-12-17T10:30:00Z",
  "assigned_by": "admin-user-uuid"
}
```

##### Get User Roles and Permissions
```bash
GET /api/v1/users/{userId}/roles
Authorization: Bearer <token>

Response (200):
{
  "roles": [
    {
      "id": "role-user-default",
      "name": "user",
      "description": "Standard user with basic permissions",
      "created_at": "2024-12-17T10:30:00Z",
      "updated_at": "2024-12-17T10:30:00Z"
    }
  ],
  "permissions": [
    {
      "id": "perm-users-read",
      "resource": "users",
      "action": "read",
      "description": "View user information",
      "created_at": "2024-12-17T10:30:00Z"
    }
  ]
}
```

##### Remove Role from User (Admin Only)
```bash
DELETE /api/v1/users/{userId}/roles/{roleId}
Authorization: Bearer <admin-token>

Response (200):
{
  "message": "role removed successfully"
}
```

#### Role-Permission Assignments

##### Assign Permission to Role (Admin Only)
```bash
POST /api/v1/roles/{roleId}/permissions
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "permission_id": "perm-uuid"
}

Response (201):
{
  "role_id": "role-uuid",
  "permission_id": "perm-uuid"
}
```

##### Assign Multiple Permissions to Role (Admin Only)
```bash
POST /api/v1/roles/{roleId}/permissions/batch
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "permission_ids": ["perm-uuid-1", "perm-uuid-2", "perm-uuid-3"]
}

Response (201):
{
  "message": "permissions assigned successfully"
}
```

##### Remove Permission from Role (Admin Only)
```bash
DELETE /api/v1/roles/{roleId}/permissions/{permissionId}
Authorization: Bearer <admin-token>

Response (200):
{
  "message": "permission removed successfully"
}
```

### Health Endpoints

```bash
# Liveness check
GET http://localhost:9090/health

# Readiness check
GET http://localhost:9090/ready
```

## Testing with curl

### Complete Flow Example

```bash
# 1. Register a new user
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "name": "Test User"
  }'

# Save the token from response
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 2. Get user profile
curl -X GET http://localhost:8080/api/users/me \
  -H "Authorization: Bearer $TOKEN"

# 3. Update user
curl -X PUT http://localhost:8080/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Updated Name"}'

# 4. Login (get new token)
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'

# 5. Delete account
curl -X DELETE http://localhost:8080/api/users/me \
  -H "Authorization: Bearer $TOKEN"
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | Yes | - | Secret key for signing JWT tokens (32+ chars recommended) |
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `BOOTSTRAP_ADMIN_EMAIL` | No | - | Email for bootstrap admin user (created on first startup) |
| `BOOTSTRAP_ADMIN_PASSWORD` | No | - | Password for bootstrap admin user |
| `BOOTSTRAP_ADMIN_NAME` | No | Admin | Name for bootstrap admin user |
| `HTTP_PORT` | No | 8080 | Main HTTP server port |
| `HEALTH_PORT` | No | 9090 | Health check server port |
| `LOG_LEVEL` | No | info | Log level (debug, info, warn, error) |

### config.toml

Bedrock-specific configuration (can be overridden by env vars):

```toml
http_port = "8080"
health_port = "9090"
log_level = "info"
```

## Database Schema

```sql
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
```

## RBAC (Role-Based Access Control)

### Concepts

Gatekeeper implements a flexible RBAC system with the following components:

#### Roles
- Named collections of permissions (e.g., "admin", "user", "moderator")
- Users can have multiple roles
- Default roles: "admin" (full access) and "user" (basic access)

#### Permissions
- Granular capabilities following the `resource:action` naming convention
- Examples: `users:read`, `users:write`, `roles:delete`, `posts:publish`
- Permissions are assigned to roles, not directly to users
- Users inherit permissions from all their assigned roles

#### JWT Token Enhancement
- JWT tokens include both `roles` and `permissions` arrays
- Permissions are flattened from all user roles for quick authorization checks
- No need for additional database lookups on every request

#### Authorization Middleware
- `RequireRole("admin")` - Requires specific role
- `RequireAnyRole("admin", "moderator")` - Requires at least one role
- `RequirePermission("users:write")` - Requires specific permission
- `RequireAnyPermission(...)` - Requires at least one permission
- `RequireAllPermissions(...)` - Requires all specified permissions

### Permission Naming Convention

Follow the `resource:action` pattern for consistency:

```
Resource Types:
- users: User management
- roles: Role management
- permissions: Permission management
- user-roles: User-role assignments

Common Actions:
- read: View/list resources
- write: Create/update resources
- delete: Delete resources
```

Examples:
```
users:read          # Can view users
users:write         # Can create/update users
users:delete        # Can delete users
roles:read          # Can view roles
roles:write         # Can create/update roles
permissions:write   # Can create permissions
user-roles:write    # Can assign/remove roles from users
```

### Default Roles and Permissions

#### Admin Role
Has all permissions:
- All `users:*` permissions
- All `roles:*` permissions
- All `permissions:*` permissions
- All `user-roles:*` permissions

#### User Role
Has basic read permissions:
- `users:read`
- `roles:read`
- `permissions:read`

### Bootstrap Admin User

On first startup, if `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` environment variables are set, an admin user will be automatically created and assigned the admin role.

```bash
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=securepassword123
BOOTSTRAP_ADMIN_NAME=Administrator
```

### Using RBAC in Your Application

When consuming Gatekeeper from other services (like Chronos):

1. **Validate the JWT token** using the same `JWT_SECRET`
2. **Extract roles and permissions** from the token claims
3. **Check permissions** before allowing actions

Example JWT claims structure:
```json
{
  "user_id": "user-uuid",
  "email": "user@example.com",
  "roles": ["user", "moderator"],
  "permissions": [
    "users:read",
    "posts:read",
    "posts:write",
    "posts:delete"
  ],
  "exp": 1702850400,
  "iat": 1702764000,
  "sub": "user-uuid"
}
```

## Security

### Password Requirements
- Minimum 8 characters
- Hashed with bcrypt (cost factor 12)

### JWT Tokens
- Signed with HS256 algorithm
- Default expiration: 24 hours
- Secret must be strong and stored in environment variables

### Best Practices
1. **Always use HTTPS in production**
2. **Use a strong JWT_SECRET** (32+ random characters)
3. **Set appropriate token expiration** (shorter for high-security apps)
4. **Enable SSL for PostgreSQL** in production
5. **Use environment variables** for secrets (never commit .env)
6. **Validate all inputs** (email format, password strength)

## Production Deployment

### Docker Deployment

```dockerfile
# Dockerfile
FROM golang:1.25.5-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o gatekeeper

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/gatekeeper .
COPY config.toml .
EXPOSE 8080 9090
CMD ["./gatekeeper"]
```

```bash
# Build
docker build -t gatekeeper .

# Run
docker run -p 8080:8080 -p 9090:9090 \
  -e JWT_SECRET="your-secret" \
  -e DATABASE_URL="postgres://..." \
  gatekeeper
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gatekeeper
spec:
  replicas: 3
  selector:
    matchLabels:
      app: gatekeeper
  template:
    metadata:
      labels:
        app: gatekeeper
    spec:
      containers:
      - name: gatekeeper
        image: gatekeeper:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: health
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: gatekeeper-secrets
              key: jwt-secret
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: gatekeeper-secrets
              key: database-url
        livenessProbe:
          httpGet:
            path: /health
            port: 9090
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Error Responses

All errors follow this format:

```json
{
  "error": "description of what went wrong"
}
```

Common status codes:
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (invalid/missing token)
- `404` - Not Found (user doesn't exist)
- `409` - Conflict (email already registered)
- `500` - Internal Server Error

## Development

### Run Tests
```bash
go test ./...
```

### Hot Reload (with air)
```bash
go install github.com/cosmtrek/air@latest
air
```

## Roadmap

Completed:
- [x] Role-based access control (RBAC)

Future enhancements:
- [ ] Comprehensive test suite
- [ ] Refresh tokens
- [ ] Email verification
- [ ] Password reset flow
- [ ] OAuth2 integration (Google, GitHub)
- [ ] Rate limiting
- [ ] Account lockout after failed logins
- [ ] Audit logging for role/permission changes
- [ ] Multi-factor authentication (MFA)
- [ ] Permission wildcards (e.g., `users:*`)
- [ ] Row-level permissions
- [ ] Time-based role assignments

## License

MIT

## Support

For issues or questions, please open an issue on GitHub.
