package unit

// Unit Tests for Password Change Database Layer
//
// These tests verify database operations for password change including:
// - Password validation against complexity requirements
// - Password settings retrieval from Redmine configuration
// - Password change with Redmine-compatible hashing
// - Security token deletion after password change
//
// Requires: Running PostgreSQL database with Redmine schema
//
// To run these tests:
//   export TEST_DATABASE_URL="postgres://redmine:redmine@localhost:5432/redmine_test?sslmode=disable"
//   go test ./tests/unit/ -v -run TestPasswordDatabase
//
// To skip database tests:
//   go test ./tests/unit/ -v -run TestPasswordDatabase -short

import (
	"context"
	"crypto/sha1"
	"fmt"
	"testing"
	"time"

	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var passwordTestDB *database.PostgreSQL

func init() {
	// Setup test database for password tests
	dbURL := "postgres://redmine:redmine@localhost:5432/redmine_test?sslmode=disable"

	var err error
	passwordTestDB, err = database.NewPostgreSQL(dbURL)
	if err != nil {
		fmt.Printf("Failed to connect to test database: %v\n", err)
		fmt.Println("Skipping password database unit tests")
		passwordTestDB = nil
		return
	}
}

// T043: Unit test - GetPasswordSettings returns default values when no settings exist
func TestPasswordDatabase_GetPasswordSettingsReturnsDefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()

	// Clear any existing settings
	_, err := passwordTestDB.ExecContext(ctx, "DELETE FROM settings WHERE name IN ('password_min_length', 'password_required_char_classes')")
	require.NoError(t, err)

	// Get password settings
	minLength, requiredCharClasses, err := passwordTestDB.GetPasswordSettings(ctx)
	require.NoError(t, err)

	// Verify defaults
	assert.Equal(t, 12, minLength)
	assert.Equal(t, []string{"lowercase", "uppercase", "numbers"}, requiredCharClasses)
}

// T043: Unit test - GetPasswordSettings reads configured values
func TestPasswordDatabase_GetPasswordSettingsReadsConfiguredValues(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()

	// Set custom settings
	_, err := passwordTestDB.ExecContext(ctx, "INSERT INTO settings (name, value) VALUES ('password_min_length', '16') ON CONFLICT (name) DO UPDATE SET value = '16'")
	require.NoError(t, err)
	_, err = passwordTestDB.ExecContext(ctx, "INSERT INTO settings (name, value) VALUES ('password_required_char_classes', '---\n- lowercase\n- uppercase\n- numbers\n- special_chars\n') ON CONFLICT (name) DO UPDATE SET value = '---\n- lowercase\n- uppercase\n- numbers\n- special_chars\n'")
	require.NoError(t, err)

	defer func() {
		// Clean up
		_, err := passwordTestDB.ExecContext(ctx, "DELETE FROM settings WHERE name IN ('password_min_length', 'password_required_char_classes')")
		require.NoError(t, err)
	}()

	// Get password settings
	minLength, requiredCharClasses, err := passwordTestDB.GetPasswordSettings(ctx)
	require.NoError(t, err)

	// Verify configured values
	assert.Equal(t, 16, minLength)
	assert.Equal(t, []string{"lowercase", "uppercase", "numbers", "special_chars"}, requiredCharClasses)
}

// T044: Unit test - ValidatePassword accepts valid passwords
func TestPasswordDatabase_ValidatePasswordAcceptsValidPasswords(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()

	// Test valid password
	validPassword := "ValidPass123!"
	err := passwordTestDB.ValidatePassword(ctx, validPassword)
	assert.NoError(t, err)
}

// T044: Unit test - ValidatePassword rejects passwords that are too short
func TestPasswordDatabase_ValidatePasswordRejectsShortPasswords(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()

	// Test password that's too short
	shortPassword := "Short1!"
	err := passwordTestDB.ValidatePassword(ctx, shortPassword)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be at least")
}

// T044: Unit test - ValidatePassword rejects passwords missing required character classes
func TestPasswordDatabase_ValidatePasswordRejectsMissingCharClasses(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()

	testCases := []struct {
		name     string
		password string
		missing  string
	}{
		{"missing lowercase", "VALIDPASS123!", "lowercase"},
		{"missing uppercase", "validpass123!", "uppercase"},
		{"missing numbers", "ValidPass!", "number"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := passwordTestDB.ValidatePassword(ctx, tc.password)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.missing)
		})
	}
}

// T045: Unit test - ChangePassword updates password with correct hashing
func TestPasswordDatabase_ChangePasswordUpdatesWithCorrectHashing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	newPassword := "NewValidPass123!"

	// Change password
	err := passwordTestDB.ChangePassword(ctx, userID, newPassword)
	require.NoError(t, err)

	// Verify password was updated in database
	var hashedPassword, salt string
	var mustChangePasswd bool
	var passwdChangedOn *time.Time
	err = passwordTestDB.QueryRowContext(ctx, "SELECT hashed_password, salt, must_change_passwd, passwd_changed_on FROM users WHERE id = $1", userID).Scan(&hashedPassword, &salt, &mustChangePasswd, &passwdChangedOn)
	require.NoError(t, err)

	// Verify must_change_passwd is cleared
	assert.False(t, mustChangePasswd)

	// Verify passwd_changed_on is set
	assert.NotNil(t, passwdChangedOn)
	assert.WithinDuration(t, time.Now(), *passwdChangedOn, 5*time.Second)

	// Verify password hashing matches Redmine algorithm
	// Redmine uses: sha1(salt + sha1(password))
	innerHash := fmt.Sprintf("%x", sha1.Sum([]byte(newPassword)))
	expectedHash := fmt.Sprintf("%x", sha1.Sum([]byte(salt+innerHash)))
	assert.Equal(t, expectedHash, hashedPassword)
}

// T045: Unit test - ChangePassword deletes security tokens
func TestPasswordDatabase_ChangePasswordDeletesSecurityTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Create some security tokens
	_, err := passwordTestDB.ExecContext(ctx, "INSERT INTO tokens (user_id, action, value, created_on) VALUES ($1, 'recovery', 'token1', NOW())", userID)
	require.NoError(t, err)
	_, err = passwordTestDB.ExecContext(ctx, "INSERT INTO tokens (user_id, action, value, created_on) VALUES ($1, 'autologin', 'token2', NOW())", userID)
	require.NoError(t, err)
	_, err = passwordTestDB.ExecContext(ctx, "INSERT INTO tokens (user_id, action, value, created_on) VALUES ($1, 'session', 'token3', NOW())", userID)
	require.NoError(t, err)

	// Verify tokens exist
	var count int
	err = passwordTestDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tokens WHERE user_id = $1 AND action IN ('recovery', 'autologin', 'session')", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Change password
	err = passwordTestDB.ChangePassword(ctx, userID, "NewValidPass123!")
	require.NoError(t, err)

	// Verify security tokens were deleted
	err = passwordTestDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tokens WHERE user_id = $1 AND action IN ('recovery', 'autologin', 'session')", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// T045: Unit test - ChangePassword rejects invalid passwords
func TestPasswordDatabase_ChangePasswordRejectsInvalidPasswords(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Try to change to invalid password
	invalidPassword := "short"
	err := passwordTestDB.ChangePassword(ctx, userID, invalidPassword)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password validation failed")
}

// T045: Unit test - ChangePassword fails for non-existent user
func TestPasswordDatabase_ChangePasswordFailsForNonExistentUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if passwordTestDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()

	// Try to change password for non-existent user
	err := passwordTestDB.ChangePassword(ctx, 99999, "ValidPass123!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update password")
}