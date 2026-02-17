package models

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenRevoked  = errors.New("refresh token has been revoked")
	ErrRefreshTokenExpired  = errors.New("refresh token has expired")
)

// RefreshToken represents a refresh token stored in the database
type RefreshToken struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	TokenHash  string    `json:"-"`
	FamilyID   string    `json:"family_id"`
	Revoked    bool      `json:"revoked"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	ReplacedBy *string   `json:"replaced_by,omitempty"`
}

// RefreshTokenRepository handles all database operations for refresh tokens
type RefreshTokenRepository struct {
	db *sql.DB
}

// NewRefreshTokenRepository creates a new refresh token repository
func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

// Create inserts a new refresh token into the database
func (r *RefreshTokenRepository) Create(userID, tokenHash, familyID string, expiresAt time.Time) (*RefreshToken, error) {
	rt := &RefreshToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		TokenHash: tokenHash,
		FamilyID:  familyID,
		ExpiresAt: expiresAt,
	}

	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, revoked, expires_at, created_at)
		VALUES ($1, $2, $3, $4, FALSE, $5, CURRENT_TIMESTAMP)
		RETURNING created_at
	`

	err := r.db.QueryRow(query, rt.ID, rt.UserID, rt.TokenHash, rt.FamilyID, rt.ExpiresAt).
		Scan(&rt.CreatedAt)
	if err != nil {
		return nil, err
	}

	return rt, nil
}

// GetByTokenHash retrieves a refresh token by its SHA-256 hash
func (r *RefreshTokenRepository) GetByTokenHash(tokenHash string) (*RefreshToken, error) {
	rt := &RefreshToken{}

	query := `
		SELECT id, user_id, token_hash, family_id, revoked, expires_at, created_at, replaced_by
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	err := r.db.QueryRow(query, tokenHash).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.TokenHash,
		&rt.FamilyID,
		&rt.Revoked,
		&rt.ExpiresAt,
		&rt.CreatedAt,
		&rt.ReplacedBy,
	)

	if err == sql.ErrNoRows {
		return nil, ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, err
	}

	return rt, nil
}

// RevokeByID marks a single refresh token as revoked and sets its replacement
func (r *RefreshTokenRepository) RevokeByID(id string, replacedBy string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = TRUE, replaced_by = $1
		WHERE id = $2
	`

	result, err := r.db.Exec(query, replacedBy, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRefreshTokenNotFound
	}

	return nil
}

// RevokeFamily revokes all refresh tokens in the same family
func (r *RefreshTokenRepository) RevokeFamily(familyID string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = TRUE
		WHERE family_id = $1 AND revoked = FALSE
	`

	_, err := r.db.Exec(query, familyID)
	return err
}

// RevokeAllForUser revokes all refresh tokens for a given user
func (r *RefreshTokenRepository) RevokeAllForUser(userID string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = TRUE
		WHERE user_id = $1 AND revoked = FALSE
	`

	_, err := r.db.Exec(query, userID)
	return err
}

// DeleteExpired removes all expired refresh tokens from the database
func (r *RefreshTokenRepository) DeleteExpired() (int64, error) {
	query := `
		DELETE FROM refresh_tokens
		WHERE expires_at < CURRENT_TIMESTAMP
	`

	result, err := r.db.Exec(query)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}
