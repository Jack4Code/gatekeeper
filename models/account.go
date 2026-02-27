package models

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrAccountNotFound    = errors.New("account not found")
	ErrAccountNameTaken   = errors.New("account name already taken")
)

// Account represents a named tenant in the system
type Account struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AccountRepository handles all database operations for accounts
type AccountRepository struct {
	db *sql.DB
}

// NewAccountRepository creates a new account repository
func NewAccountRepository(db *sql.DB) *AccountRepository {
	return &AccountRepository{db: db}
}

// Create inserts a new account with a generated UUID
func (r *AccountRepository) Create(name string) (*Account, error) {
	account := &Account{
		ID:   uuid.New().String(),
		Name: name,
	}

	query := `
		INSERT INTO accounts (id, name, created_at, updated_at)
		VALUES ($1, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		RETURNING created_at, updated_at
	`

	err := r.db.QueryRow(query, account.ID, account.Name).
		Scan(&account.CreatedAt, &account.UpdatedAt)

	if err != nil {
		if isDuplicateKeyError(err, "idx_accounts_name") {
			return nil, ErrAccountNameTaken
		}
		return nil, err
	}

	return account, nil
}

// GetByName retrieves an account by its unique name
func (r *AccountRepository) GetByName(name string) (*Account, error) {
	account := &Account{}

	query := `
		SELECT id, name, created_at, updated_at
		FROM accounts
		WHERE name = $1
	`

	err := r.db.QueryRow(query, name).Scan(
		&account.ID,
		&account.Name,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrAccountNotFound
	}
	if err != nil {
		return nil, err
	}

	return account, nil
}

// GetByID retrieves an account by its UUID
func (r *AccountRepository) GetByID(id string) (*Account, error) {
	account := &Account{}

	query := `
		SELECT id, name, created_at, updated_at
		FROM accounts
		WHERE id = $1
	`

	err := r.db.QueryRow(query, id).Scan(
		&account.ID,
		&account.Name,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrAccountNotFound
	}
	if err != nil {
		return nil, err
	}

	return account, nil
}
