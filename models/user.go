package models

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailAlreadyExists = errors.New("email already exists")
)

// User represents a user in the system
type User struct {
	ID           string    `json:"id"`
	AccountID    string    `json:"account_id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // Never expose in JSON
	Name         string    `json:"name"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserRepository handles all database operations for users
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create inserts a new user into the database
func (r *UserRepository) Create(accountID, email, passwordHash, name string) (*User, error) {
	user := &User{
		ID:           uuid.New().String(),
		AccountID:    accountID,
		Email:        email,
		PasswordHash: passwordHash,
		Name:         name,
	}

	query := `
		INSERT INTO users (id, account_id, email, password_hash, name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		RETURNING created_at, updated_at
	`

	err := r.db.QueryRow(query, user.ID, user.AccountID, user.Email, user.PasswordHash, user.Name).
		Scan(&user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if isDuplicateKeyError(err, "users_email_account_id_key") {
			return nil, ErrEmailAlreadyExists
		}
		return nil, err
	}

	return user, nil
}

// GetByID retrieves a user by their ID
func (r *UserRepository) GetByID(id string) (*User, error) {
	user := &User{}

	query := `
		SELECT id, account_id, email, password_hash, name, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.AccountID,
		&user.Email,
		&user.PasswordHash,
		&user.Name,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetByEmail retrieves a user by their email address within a specific account
func (r *UserRepository) GetByEmail(accountID, email string) (*User, error) {
	user := &User{}

	query := `
		SELECT id, account_id, email, password_hash, name, created_at, updated_at
		FROM users
		WHERE account_id = $1 AND email = $2
	`

	err := r.db.QueryRow(query, accountID, email).Scan(
		&user.ID,
		&user.AccountID,
		&user.Email,
		&user.PasswordHash,
		&user.Name,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Update updates a user's information
func (r *UserRepository) Update(id, name string) (*User, error) {
	query := `
		UPDATE users
		SET name = $1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
		RETURNING id, account_id, email, password_hash, name, created_at, updated_at
	`

	user := &User{}
	err := r.db.QueryRow(query, name, id).Scan(
		&user.ID,
		&user.AccountID,
		&user.Email,
		&user.PasswordHash,
		&user.Name,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Delete removes a user from the database
func (r *UserRepository) Delete(id string) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// List retrieves all users (with optional pagination)
func (r *UserRepository) List(limit, offset int) ([]*User, error) {
	query := `
		SELECT id, account_id, email, password_hash, name, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []*User{}
	for rows.Next() {
		user := &User{}
		err := rows.Scan(
			&user.ID,
			&user.AccountID,
			&user.Email,
			&user.PasswordHash,
			&user.Name,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}
