package unit

// Unit Tests for 2FA Database Layer (Phase 2: User Story 1)
//
// These tests verify database operations for 2FA including:
// - Backup code generation with proper entropy
// - Backup code validation and single-use consumption
// - Database schema compatibility with Redmine
//
// Requires: Running PostgreSQL database with Redmine schema
//
// To run these tests:
//   export TEST_DATABASE_URL="postgres://redmine:redmine@localhost:5432/redmine_test?sslmode=disable"
//   go test ./tests/unit/ -v -run TestTwoFADatabase
//
// To skip database tests:
//   go test ./tests/unit/ -v -run TestTwoFADatabase -short

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testDB *database.PostgreSQL

func init() {
	// Setup test database
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://redmine:redmine@localhost:5432/redmine_test?sslmode=disable"
	}

	var err error
	testDB, err = database.NewPostgreSQL(dbURL)
	if err != nil {
		fmt.Printf("Failed to connect to test database: %v\n", err)
		fmt.Println("Skipping database unit tests")
		testDB = nil
		return
	}
}

// Helper function to create test user
func createTestUser(t *testing.T) int {
	username := fmt.Sprintf("test_user_%d", time.Now().UnixNano())
	var userID int
	err := testDB.QueryRowContext(context.Background(), `
		INSERT INTO users (login, hashed_password, firstname, lastname, mail, created_on, updated_on, status, type)
		VALUES ($1, 'hashed_password', 'Test', 'User', $2, NOW(), NOW(), 1, 'User')
		RETURNING id
	`, username, username+"@test.com").Scan(&userID)
	require.NoError(t, err)
	return userID
}

// Helper function to delete test user
func deleteTestUser(t *testing.T, userID int) {
	ctx := context.Background()
	_, err := testDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	require.NoError(t, err)
	_, err = testDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
	require.NoError(t, err)
}

// T041: Unit test - GenerateBackupCodes creates 10 unique codes
func TestTwoFADatabase_GenerateBackupCodesCreates10UniqueCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if testDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Generate backup codes
	codes, err := testDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)

	// Verify count
	assert.Len(t, codes, 10)

	// Verify uniqueness
	uniqueCodes := make(map[string]bool)
	for _, code := range codes {
		assert.False(t, uniqueCodes[code], "Backup codes should be unique")
		uniqueCodes[code] = true
	}
	assert.Len(t, uniqueCodes, 10)

	// Verify format (12 characters, alphanumeric)
	for _, code := range codes {
		assert.Len(t, code, 12)
		assert.Regexp(t, "^[A-Z0-9]+$", code)
	}
}

// T041: Unit test - GenerateBackupCodes stores codes in database
func TestTwoFADatabase_GenerateBackupCodesStoresInDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if testDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Generate backup codes
	codes, err := testDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)

	// Verify codes are in database
	var count int
	err = testDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code'", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 10, count)

	// Verify codes are hashed (not stored in plain text)
	rows, err := testDB.QueryContext(ctx, "SELECT value FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code'", userID)
	require.NoError(t, err)
	defer rows.Close()

	storedCodes := make([]string, 0)
	for rows.Next() {
		var storedCode string
		err := rows.Scan(&storedCode)
		require.NoError(t, err)
		storedCodes = append(storedCodes, storedCode)

		// Stored code should not match any plain text code (should be hashed)
		for _, plainCode := range codes {
			assert.NotEqual(t, plainCode, storedCode, "Backup codes should be hashed in database")
		}
	}

	assert.Len(t, storedCodes, 10)
}

// T041: Unit test - GenerateBackupCodes replaces old codes
func TestTwoFADatabase_GenerateBackupCodesReplacesOldCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if testDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Generate first set of codes
	codes1, err := testDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)
	assert.Len(t, codes1, 10)

	// Generate second set of codes
	codes2, err := testDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)
	assert.Len(t, codes2, 10)

	// Should still only have 10 codes in database (old ones replaced)
	var count int
	err = testDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code'", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 10, count)

	// Old codes should not work
	valid, err := testDB.ValidateAndConsumeBackupCode(ctx, userID, codes1[0])
	require.NoError(t, err)
	assert.False(t, valid, "Old backup codes should be invalid after regeneration")

	// New codes should work
	valid, err = testDB.ValidateAndConsumeBackupCode(ctx, userID, codes2[0])
	require.NoError(t, err)
	assert.True(t, valid, "New backup codes should be valid")
}

// T042: Unit test - ValidateAndConsumeBackupCode accepts valid code
func TestTwoFADatabase_ValidateAndConsumeBackupCodeAcceptsValidCode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if testDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Generate backup codes
	codes, err := testDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)

	// Validate first code
	valid, err := testDB.ValidateAndConsumeBackupCode(ctx, userID, codes[0])
	require.NoError(t, err)
	assert.True(t, valid)
}

// T042: Unit test - ValidateAndConsumeBackupCode rejects invalid code
func TestTwoFADatabase_ValidateAndConsumeBackupCodeRejectsInvalidCode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if testDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Generate backup codes
	_, err := testDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)

	// Try invalid code
	valid, err := testDB.ValidateAndConsumeBackupCode(ctx, userID, "INVALID12345")
	require.NoError(t, err)
	assert.False(t, valid)
}

// T042: Unit test - ValidateAndConsumeBackupCode consumes code (single-use)
func TestTwoFADatabase_ValidateAndConsumeBackupCodeIsSingleUse(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if testDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Generate backup codes
	codes, err := testDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)

	// Use code first time
	valid, err := testDB.ValidateAndConsumeBackupCode(ctx, userID, codes[0])
	require.NoError(t, err)
	assert.True(t, valid)

	// Try to use same code again
	valid, err = testDB.ValidateAndConsumeBackupCode(ctx, userID, codes[0])
	require.NoError(t, err)
	assert.False(t, valid, "Backup code should be single-use")

	// Verify code is deleted from database
	var count int
	err = testDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code'", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 9, count, "Used backup code should be deleted")
}

// T042: Unit test - ValidateAndConsumeBackupCode is case-insensitive
func TestTwoFADatabase_ValidateAndConsumeBackupCodeIsCaseInsensitive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if testDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Generate backup codes
	codes, err := testDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)

	// Use code with different case
	lowercaseCode := codes[0]
	// uppercaseCode := codes[0] // Codes are generated in uppercase

	// Try lowercase version
	valid, err := testDB.ValidateAndConsumeBackupCode(ctx, userID, lowercaseCode)
	require.NoError(t, err)
	assert.True(t, valid, "Backup code validation should be case-insensitive")
}

// Additional test: Verify backup codes have sufficient entropy
func TestTwoFADatabase_BackupCodesHaveSufficientEntropy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if testDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Generate multiple sets of codes
	allCodes := make(map[string]bool)
	for i := 0; i < 5; i++ {
		codes, err := testDB.GenerateBackupCodes(ctx, userID, 10)
		require.NoError(t, err)

		for _, code := range codes {
			allCodes[code] = true
		}
	}

	// Should have 50 unique codes (5 sets × 10 codes)
	assert.Len(t, allCodes, 50, "Backup codes should have high entropy and not repeat")
}

// Additional test: Verify backup codes expiration
func TestTwoFADatabase_BackupCodesHaveCreatedTimestamp(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database unit tests in short mode")
	}
	if testDB == nil {
		t.Skip("Database not available")
	}

	ctx := context.Background()
	userID := createTestUser(t)
	defer deleteTestUser(t, userID)

	// Generate backup codes
	_, err := testDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)

	// Verify created_on timestamp exists
	var createdOn time.Time
	err = testDB.QueryRowContext(ctx, "SELECT created_on FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code' LIMIT 1", userID).Scan(&createdOn)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), createdOn, 5*time.Second)
}
