# Gatekeeper

An authentication service built with [Bedrock](https://github.com/Jack4Code/bedrock) and PostgreSQL.

## Features

- ✅ User registration with email/password
- ✅ User login with JWT token generation
- ✅ Protected routes with JWT validation
- ✅ User profile management (get, update, delete)
- ✅ PostgreSQL database with proper schema
- ✅ Input validation (email format, password length)
- ✅ Secure password hashing with bcrypt
- ✅ Repository pattern for clean database access
- ✅ Graceful shutdown
- ✅ Health checks for orchestration (Kubernetes/Nomad)

## Tech Stack

- **Framework**: Bedrock (custom Go framework)
- **Database**: PostgreSQL
- **Auth**: JWT (JSON Web Tokens)
- **Password Hashing**: bcrypt
- **Database Driver**: lib/pq

## Project Structure

```
gatekeeper/
├── main.go                       # Main application & handlers
├── models/
│   └── user.go                   # User model & repository
├── migrations/
│   └── 001_create_users_table.sql  # Database schema
├── config.toml                   # Bedrock configuration
├── .env.example                  # Environment variables template
├── go.mod                        # Dependencies
└── README.md                     # This file
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

# Run migrations
psql -d authdb -U authuser -f migrations/001_create_users_table.sql
```

### 3. Configure Environment

```bash
# Copy example env file
cp .env.example .env

# Edit .env and set:
# - JWT_SECRET (use a strong random string)
# - DATABASE_URL (your postgres connection string)
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
| `JWT_SECRET` | Yes | - | Secret key for signing JWT tokens |
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
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

Future enhancements:
- [ ] Refresh tokens
- [ ] Email verification
- [ ] Password reset flow
- [ ] OAuth2 integration (Google, GitHub)
- [ ] Role-based access control (RBAC)
- [ ] Rate limiting
- [ ] Account lockout after failed logins
- [ ] Audit logging
- [ ] Multi-factor authentication (MFA)

## License

MIT

## Support

For issues or questions, please open an issue on GitHub.
