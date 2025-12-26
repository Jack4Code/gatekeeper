package models

import "strings"

// isDuplicateKeyError checks if an error is a PostgreSQL duplicate key violation
// for a specific constraint name
func isDuplicateKeyError(err error, constraintName string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "duplicate key value violates unique constraint") &&
		strings.Contains(err.Error(), constraintName)
}
