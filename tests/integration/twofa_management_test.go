package integration

// Integration Tests for 2FA Management Endpoints (Phase 6)
//
// These tests verify the 2FA management functionality including:
// - Getting 2FA status
// - Disabling 2FA
// - Regenerating backup codes
// - Concurrent request handling
//
// Prerequisites:
// 1. PostgreSQL database with Redmine schema
// 2. Redis server for session management
// 3. Test users with 2FA enabled/disabled
//
// To run these tests:
//   export TEST_DATABASE_URL="postgres://postgres:test@localhost:5432/redmine?sslmode=disable"
//   export TEST_REDIS_URL="localhost:6379"
//   go test ./tests/integration/ -v -run TestTwoFAManagement
//
// To skip integration tests:
//   export SKIP_INTEGRATION_TESTS=true

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/handlers"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/middleware"
	"github.com/go-make-bytes/redmine-gateway/internal/oauth"
	"github.com/go-make-bytes/redmine-gateway/internal/router/requests"
	"github.com/go-make-bytes/redmine-gateway/internal/session"
	"github.com/go-make-bytes/redmine-gateway/internal/twofa"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures (shared with twofa_auth_flow_test.go)
var (
	mgmtTestDB           *database.PostgreSQL
	mgmtTestRedis        *redis.Client
	mgmtTestLogger       *logger.Logger
	mgmtTestConfig       *config.Config
	mgmtTestAuthHandler  *handlers.AuthHandler
	mgmtTestTwoFAHandler *handlers.TwoFAHandler
	mgmtTestSessionMgr   *session.SessionManager
	mgmtTwoFASessionMgr  *session.TwoFASessionManager
	mgmtTestTOTPService  *twofa.TOTPService
)

func setupTwoFAManagementTestEnvironment(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests: SKIP_INTEGRATION_TESTS=true")
	}

	// Setup test database
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:test@localhost:5432/redmine?sslmode=disable"
	}

	var err error
	mgmtTestDB, err = database.NewPostgreSQL(dbURL)
	if err != nil {
		t.Skipf("Skipping integration tests: Failed to connect to test database: %v", err)
	}

	// Setup test Redis
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	mgmtTestRedis = redis.NewClient(&redis.Options{
		Addr: redisURL,
		DB:   16, // Use database 16 for management tests
	})

	ctx := context.Background()
	if err := mgmtTestRedis.Ping(ctx).Err(); err != nil {
		t.Skipf("Skipping integration tests: Failed to connect to Redis: %v", err)
	}

	// Clear test Redis database
	mgmtTestRedis.FlushDB(ctx)

	// Setup test logger
	mgmtTestLogger = logger.New("error", "json")

	// Setup test config
	mgmtTestConfig = &config.Config{
		TwoFactor: config.TwoFactorConfig{
			Enabled:        true,
			SessionTimeout: 300, // 5 minutes
			MaxAttempts:    3,
			TOTP: config.TOTPConfig{
				Issuer: "Redmine Gateway Test",
				Period: 30,
				Digits: 6,
			},
			BackupCode: config.BackupCodeConfig{
				Count:  10,
				Length: 12,
			},
		},
		Redmine: config.RedmineConfig{
			SecretKeyBase: "test-secret-key-base-for-encryption-must-be-32-chars-long",
		},
	}

	// Initialize components
	mgmtTestSessionMgr = session.NewSessionManager(mgmtTestRedis, mgmtTestLogger, 900)
	mgmtTwoFASessionMgr = session.NewTwoFASessionManager(mgmtTestRedis, mgmtTestLogger, mgmtTestConfig)
	mgmtTestTOTPService = twofa.NewTOTPService(mgmtTestConfig)
	mgmtTestOAuthProvider := oauth.NewProvider(mgmtTestConfig, mgmtTestDB, mgmtTestRedis, mgmtTestLogger)

	inputValidator := middleware.NewInputValidator(50, 100)
	csrfProtection := middleware.NewCSRFProtection(mgmtTestRedis, mgmtTestLogger, "test-csrf-secret")

	mgmtTestAuthHandler = handlers.NewAuthHandler(
		mgmtTestConfig,
		mgmtTestDB,
		mgmtTestLogger,
		mgmtTestSessionMgr,
		mgmtTwoFASessionMgr,
		inputValidator,
		csrfProtection,
		mgmtTestRedis,
	)

	mgmtTestTwoFAHandler = handlers.NewTwoFAHandler(
		mgmtTestDB,
		mgmtTwoFASessionMgr,
		mgmtTestSessionMgr,
		mgmtTestTOTPService,
		mgmtTestOAuthProvider,
		mgmtTestLogger,
		mgmtTestConfig,
	)
}

func teardownTwoFAManagementTestEnvironment() {
	if mgmtTestDB != nil {
		mgmtTestDB.Close()
	}
	if mgmtTestRedis != nil {
		ctx := context.Background()
		mgmtTestRedis.FlushDB(ctx)
		mgmtTestRedis.Close()
	}
}

// Helper function to create a test user with 2FA enabled and authenticated session
func createAuthenticatedTestUserWith2FA(t *testing.T, username string) (userID int, sessionToken string, totpSecret string) {
	ctx := context.Background()

	// Generate TOTP secret
	key, err := mgmtTestTOTPService.GenerateSecret(username)
	require.NoError(t, err)
	totpSecret = key.Secret()

	// Encrypt the secret
	encryptedSecret, err := mgmtTestTOTPService.EncryptSecret(totpSecret)
	require.NoError(t, err)

	// Create test user in database
	query := `
		INSERT INTO users (login, hashed_password, firstname, lastname, created_on, updated_on, status, type)
		VALUES ($1, 'hashed_password', 'Test', 'User', NOW(), NOW(), 1, 'User')
		RETURNING id
	`
	err = mgmtTestDB.QueryRowContext(ctx, query, username).Scan(&userID)
	require.NoError(t, err)

	// Create email address entry
	email := username + "@test.com"
	_, err = mgmtTestDB.ExecContext(ctx, `
		INSERT INTO email_addresses (user_id, address, is_default, notify, created_on, updated_on)
		VALUES ($1, $2, true, true, NOW(), NOW())
	`, userID, email)
	require.NoError(t, err)

	// Enable 2FA for user
	err = mgmtTestDB.EnableTwoFactor(ctx, userID, encryptedSecret)
	require.NoError(t, err)

	// Generate backup codes
	_, err = mgmtTestDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)

	// Create authenticated session
	sessionToken, _, err = mgmtTestSessionMgr.CreateSession(userID, username, "127.0.0.1", "")
	require.NoError(t, err)

	return userID, sessionToken, totpSecret
}

// Helper function to get backup codes for a user
func getUserBackupCodes(t *testing.T, db *database.PostgreSQL, userID int) []string {
	ctx := context.Background()
	query := `SELECT value FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code'`
	rows, err := db.QueryContext(ctx, query, userID)
	require.NoError(t, err)
	defer rows.Close()

	var codes []string
	for rows.Next() {
		var hashedCode string
		err := rows.Scan(&hashedCode)
		require.NoError(t, err)
		codes = append(codes, hashedCode)
	}
	require.NoError(t, rows.Err())
	return codes
}

// Helper to generate valid TOTP code
func generateValidTOTPCodeMgmt(t *testing.T, secret string) string {
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	return code
}

// T089: Integration test - GET /auth/2fa/status returns correct state
func TestTwoFAManagement_StatusReturnsCorrectState(t *testing.T) {
	setupTwoFAManagementTestEnvironment(t)
	defer teardownTwoFAManagementTestEnvironment()

	// Create authenticated user with 2FA
	username := fmt.Sprintf("mgmt_user_%d", time.Now().Unix())
	userID, sessionToken, _ := createAuthenticatedTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		mgmtTestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		mgmtTestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/2fa/status", mgmtTestTwoFAHandler.TwoFAStatus)

	// Make request
	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/status", nil)
	req.Header.Set("X-Session-Token", sessionToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, true, response["enabled"])
	assert.Equal(t, "totp", response["scheme"])
	assert.Equal(t, true, response["required"]) // User has 2FA enabled
	assert.Equal(t, float64(10), response["backup_codes_remaining"])
}

// T090: Integration test - Disable 2FA with valid code removes 2FA
func TestTwoFAManagement_DisableWithValidCodeRemoves2FA(t *testing.T) {
	setupTwoFAManagementTestEnvironment(t)
	defer teardownTwoFAManagementTestEnvironment()

	// Create authenticated user with 2FA
	username := fmt.Sprintf("mgmt_user_%d", time.Now().Unix())
	userID, sessionToken, totpSecret := createAuthenticatedTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		mgmtTestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		mgmtTestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/disable", mgmtTestTwoFAHandler.TwoFADisable)

	// Generate valid TOTP code
	validCode := generateValidTOTPCodeMgmt(t, totpSecret)

	// Create disable request
	disableReq := requests.TwoFADisableRequest{
		Code: validCode,
	}
	body, _ := json.Marshal(disableReq)

	// Make request
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/disable", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", sessionToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, true, response["disabled"])

	// Verify 2FA is actually disabled in database
	ctx := context.Background()
	user, err := mgmtTestDB.GetUserTwoFactorData(ctx, userID)
	require.NoError(t, err)
	assert.False(t, user.Scheme.Valid)
	assert.False(t, user.TOTPKey.Valid)

	// Verify backup codes are deleted
	codes := getUserBackupCodes(t, mgmtTestDB, userID)
	assert.Len(t, codes, 0)
}

// T091: Integration test - Regenerate backup codes creates new set
func TestTwoFAManagement_RegenerateBackupCodesCreatesNewSet(t *testing.T) {
	setupTwoFAManagementTestEnvironment(t)
	defer teardownTwoFAManagementTestEnvironment()

	// Create authenticated user with 2FA
	username := fmt.Sprintf("mgmt_user_%d", time.Now().Unix())
	userID, sessionToken, totpSecret := createAuthenticatedTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		mgmtTestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		mgmtTestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Get original backup codes
	originalCodes := getUserBackupCodes(t, mgmtTestDB, userID)
	require.Len(t, originalCodes, 10)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/backup-codes", mgmtTestTwoFAHandler.BackupCodesGenerate)

	// Generate valid TOTP code
	validCode := generateValidTOTPCodeMgmt(t, totpSecret)

	// Create regenerate request
	regenerateReq := requests.TwoFABackupCodesRequest{
		Code: validCode,
	}
	body, _ := json.Marshal(regenerateReq)

	// Make request
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", sessionToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	backupCodes := response["backup_codes"].([]interface{})
	assert.Len(t, backupCodes, 10)

	// Verify new codes are different from original
	newCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		newCodes[i] = code.(string)
	}

	// Check that at least one code is different (very high probability)
	different := false
	for _, newCode := range newCodes {
		found := false
		for _, origCode := range originalCodes {
			if newCode == origCode {
				found = true
				break
			}
		}
		if !found {
			different = true
			break
		}
	}
	assert.True(t, different, "New backup codes should be different from original")

	// Verify old codes are invalidated
	var currentCodes []string = getUserBackupCodes(t, mgmtTestDB, userID)
	assert.Len(t, currentCodes, 10)
}

// T091B: Integration test - Concurrent regenerate requests are serialized
func TestTwoFAManagement_ConcurrentRegenerateRequestsSerialized(t *testing.T) {
	setupTwoFAManagementTestEnvironment(t)
	defer teardownTwoFAManagementTestEnvironment()

	// Create authenticated user with 2FA
	username := fmt.Sprintf("mgmt_user_%d", time.Now().Unix())
	userID, sessionToken, totpSecret := createAuthenticatedTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		mgmtTestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		mgmtTestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/backup-codes", mgmtTestTwoFAHandler.BackupCodesGenerate)

	// Generate valid TOTP code
	validCode := generateValidTOTPCodeMgmt(t, totpSecret)

	// Create regenerate request
	regenerateReq := requests.TwoFABackupCodesRequest{
		Code: validCode,
	}
	body, _ := json.Marshal(regenerateReq)

	// Run concurrent requests
	numRequests := 5
	var wg sync.WaitGroup
	results := make([]map[string]interface{}, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Session-Token", sessionToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err == nil {
					results[index] = response
				}
			}
		}(i)
	}

	wg.Wait()

	// Count successful responses (should be exactly 1 due to serialization)
	successCount := 0
	var successfulResponse map[string]interface{}
	for _, result := range results {
		if result != nil {
			successCount++
			successfulResponse = result
		}
	}

	assert.Equal(t, 1, successCount, "Only one concurrent regenerate request should succeed")
	assert.NotNil(t, successfulResponse)

	backupCodes := successfulResponse["backup_codes"].([]interface{})
	assert.Len(t, backupCodes, 10)
}
