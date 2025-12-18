# Quick Start Guide

Get Gatekeeper running in under 5 minutes.

## Option 1: Docker Compose (Recommended for Development)

Easiest way to get started. Automatically sets up Postgres and Gatekeeper.

```bash
# 1. Set JWT secret
export JWT_SECRET="my-super-secret-key-123"

# 2. Start everything
docker-compose up -d

# 3. Test it
curl http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","name":"Test User"}'
```

The service should now be running on http://localhost:8080

**To stop:**
```bash
docker-compose down
```

**To reset database:**
```bash
docker-compose down -v  # Removes volumes (data)
docker-compose up -d
```

## Option 2: Local Development (Without Docker)

### Prerequisites
- Go 1.25.5+
- PostgreSQL 12+

### Steps

```bash
# 1. Setup database
createdb authdb
psql -d authdb -c "CREATE USER authuser WITH PASSWORD 'authpass';"
psql -d authdb -c "GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;"

# 2. Run migrations
psql -d authdb -U authuser -f migrations/001_create_users_table.sql

# 3. Create .env file
cp .env.example .env

# 4. Edit .env and set:
#    - JWT_SECRET (use a strong random string)
#    - DATABASE_URL (already set for local postgres)

# 5. Install dependencies
go mod tidy

# 6. Run Gatekeeper
export $(cat .env | xargs)
go run main.go
```

**Or use Make:**
```bash
make .env              # Create .env from template
make db-setup          # Create database
make db-migrate        # Run migrations
# Edit .env with your JWT_SECRET
make run               # Start Gatekeeper
```

## Testing Gatekeeper

### 1. Register a User
```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "securepassword123",
    "name": "Alice Smith"
  }'
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "alice@example.com",
    "name": "Alice Smith",
    "created_at": "2024-12-17T10:30:00Z",
    "updated_at": "2024-12-17T10:30:00Z"
  }
}
```

**Save the token!** You'll need it for authenticated requests.

### 2. Login
```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "securepassword123"
  }'
```

### 3. Get User Profile (Protected)
```bash
# Replace <TOKEN> with the token from register/login
curl -X GET http://localhost:8080/api/users/me \
  -H "Authorization: Bearer <TOKEN>"
```

### 4. Update User Profile (Protected)
```bash
curl -X PUT http://localhost:8080/api/users/me \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice Johnson"}'
```

### 5. Check Health
```bash
# Liveness
curl http://localhost:9090/health

# Readiness
curl http://localhost:9090/ready
```

## Common Issues

### "JWT_SECRET environment variable is required"
**Solution:** Set JWT_SECRET in your .env file or export it:
```bash
export JWT_SECRET="your-secret-key"
```

### "DATABASE_URL environment variable is required"
**Solution:** Set DATABASE_URL in your .env file:
```bash
DATABASE_URL=postgres://authuser:authpass@localhost:5432/authdb?sslmode=disable
```

### "connection refused" when connecting to database
**Solution:** Make sure PostgreSQL is running:
```bash
# macOS
brew services start postgresql

# Linux
sudo systemctl start postgresql

# Check if it's running
psql -U postgres -c "SELECT 1"
```

### Database authentication failed
**Solution:** Recreate the user with the correct password:
```bash
psql -d authdb
DROP USER IF EXISTS authuser;
CREATE USER authuser WITH PASSWORD 'authpass';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
\q
```

### Port already in use
**Solution:** Either:
1. Stop the process using the port
2. Change HTTP_PORT or HEALTH_PORT in .env

```bash
# Find what's using port 8080
lsof -i :8080

# Kill it
kill -9 <PID>
```
