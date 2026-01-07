package integration

// Integration Tests for 2FA Authentication Flow (Phase 3: User Story 1)
//
// These tests verify the complete 2FA authentication flow including:
// - Login challenge for 2FA-enabled users
// - TOTP code verification
// - Invalid code handling and attempt tracking
// - Account lockout after max failed attempts
// - Session expiration after timeout
// - Backup code recovery
//
// Prerequisites:
// 1. PostgreSQL database with Redmine schema
// 2. Redis server for session management
// 3. Test users with 2FA enabled/disabled
//
// To run these tests:
//   export TEST_DATABASE_URL="postgres://postgres:test@localhost:5432/redmine?sslmode=disable"
//   export TEST_REDIS_URL="localhost:6379"
//   go test ./tests/integration/ -v -run TestTwoFA
//
// To skip integration tests:
//   export SKIP_INTEGRATION_TESTS=true

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
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
	"github.com/go-make-bytes/redmine-gateway/internal/router/responses"
	"github.com/go-make-bytes/redmine-gateway/internal/session"
	"github.com/go-make-bytes/redmine-gateway/internal/twofa"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures
var (
	twoFATestDB           *database.PostgreSQL
	twoFATestRedis        *redis.Client
	twoFATestLogger       *logger.Logger
	twoFATestConfig       *config.Config
	twoFATestAuthHandler  *handlers.AuthHandler
	twoFATestTwoFAHandler *handlers.TwoFAHandler
	twoFATestSessionMgr   *session.SessionManager
	twoFATwoFASessionMgr  *session.TwoFASessionManager
	twoFATestTOTPService  *twofa.TOTPService
)

func setupTwoFATestEnvironment(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests: SKIP_INTEGRATION_TESTS=true")
	}

	// Setup test database
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:test@localhost:5432/redmine?sslmode=disable"
	}

	var err error
	twoFATestDB, err = database.NewPostgreSQL(dbURL)
	if err != nil {
		t.Skipf("Skipping integration tests: Failed to connect to test database: %v", err)
	}

	// Setup test Redis
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	twoFATestRedis = redis.NewClient(&redis.Options{
		Addr: redisURL,
		DB:   15, // Use database 15 for testing
	})

	ctx := context.Background()
	if err := twoFATestRedis.Ping(ctx).Err(); err != nil {
		t.Skipf("Skipping integration tests: Failed to connect to Redis: %v", err)
	}

	// Clear test Redis database
	twoFATestRedis.FlushDB(ctx)

	// Setup test logger
	twoFATestLogger = logger.New("error", "json")

	// Setup test config
	twoFATestConfig = &config.Config{
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
				Length: 8,
			},
		},
		Redmine: config.RedmineConfig{
			SecretKeyBase: "test-secret-key-base-for-encryption-must-be-32-chars-long",
		},
	}

	// Initialize components
	twoFATestSessionMgr = session.NewSessionManager(twoFATestRedis, twoFATestLogger, 900, "test:")
	twoFATwoFASessionMgr = session.NewTwoFASessionManager(twoFATestRedis, twoFATestLogger, twoFATestConfig, "test:")
	twoFATestTOTPService = twofa.NewTOTPService(twoFATestConfig)
	twoFATestOAuthProvider := oauth.NewProvider(twoFATestConfig, twoFATestDB, twoFATestRedis, twoFATestLogger, "test:")

	inputValidator := middleware.NewInputValidator(50, 100)
	csrfProtection := middleware.NewCSRFProtection(twoFATestRedis, twoFATestLogger, "test-csrf-secret", "test:")

	twoFATestAuthHandler = handlers.NewAuthHandler(
		twoFATestConfig,
		twoFATestDB,
		twoFATestLogger,
		twoFATestSessionMgr,
		twoFATwoFASessionMgr,
		inputValidator,
		csrfProtection,
		twoFATestRedis,
	)

	twoFATestTwoFAHandler = handlers.NewTwoFAHandler(
		twoFATestDB,
		twoFATwoFASessionMgr,
		twoFATestSessionMgr,
		twoFATestTOTPService,
		twoFATestOAuthProvider,
		twoFATestLogger,
		twoFATestConfig,
	)
}

func teardownTwoFATestEnvironment() {
	if twoFATestDB != nil {
		twoFATestDB.Close()
	}
	if twoFATestRedis != nil {
		ctx := context.Background()
		twoFATestRedis.FlushDB(ctx)
		twoFATestRedis.Close()
	}
}

// Helper function to create a test user with 2FA enabled
func createTestUserWith2FA(t *testing.T, username string) (userID int, totpSecret string) {
	ctx := context.Background()

	// Generate TOTP secret
	key, err := twoFATestTOTPService.GenerateSecret(username)
	require.NoError(t, err)
	totpSecret = key.Secret()

	// Encrypt the secret
	encryptedSecret, err := twoFATestTOTPService.EncryptSecret(totpSecret)
	require.NoError(t, err)

	// Generate proper Redmine-style password hash
	password := "password"
	salt := generateRandomString(32) // Generate a random salt
	hashedPassword := hashRedminePassword(password, salt)

	// Create test user in database (simplified - you may need to adjust based on your schema)
	// This assumes you have a test user creation helper or fixture
	query := `
		INSERT INTO users (login, hashed_password, salt, firstname, lastname, created_on, updated_on, status, type)
		VALUES ($1, $2, $3, 'Test', 'User', NOW(), NOW(), 1, 'User')
		RETURNING id
	`
	err = twoFATestDB.QueryRowContext(ctx, query, username, hashedPassword, salt).Scan(&userID)
	require.NoError(t, err)

	// Create email address entry
	email := username + "@test.com"
	_, err = twoFATestDB.ExecContext(ctx, `
		INSERT INTO email_addresses (user_id, address, is_default, notify, created_on, updated_on)
		VALUES ($1, $2, true, true, NOW(), NOW())
	`, userID, email)
	require.NoError(t, err)

	// Enable 2FA for user
	err = twoFATestDB.EnableTwoFactor(ctx, userID, encryptedSecret)
	require.NoError(t, err)

	return userID, totpSecret
}

// Helper to generate valid TOTP code
func generateValidTOTPCode(t *testing.T, secret string) string {
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	return code
}

// Helper function to hash password using Redmine's algorithm
func hashRedminePassword(password, salt string) string {
	innerHash := fmt.Sprintf("%x", sha1.Sum([]byte(password)))
	outerHash := fmt.Sprintf("%x", sha1.Sum([]byte(salt+innerHash)))
	return outerHash
}

// Helper function to generate random string
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// T046: Integration test - Login with 2FA user returns challenge
func TestTwoFAAuthFlow_LoginReturnsChallenge(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user with 2FA enabled
	username := fmt.Sprintf("twofa_user_%d", time.Now().Unix())
	userID, _ := createTestUserWith2FA(t, username)
	defer func() {
		// Cleanup: delete test user
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", twoFATestAuthHandler.Login)

	// Create login request
	loginReq := requests.AuthRequest{
		Username: username,
		Password: "password",
	}
	body, _ := json.Marshal(loginReq)

	// Make request
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response responses.TwoFAChallengeResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response.RequiresTwoFA)
	assert.NotEmpty(t, response.SessionToken)
	assert.False(t, response.EnrollmentMode) // User already has 2FA set up
	assert.Equal(t, 300, response.TimeoutSeconds)
	assert.Equal(t, 3, response.MaxAttempts)
}

// T047: Integration test - Valid TOTP code grants access
func TestTwoFAAuthFlow_ValidTOTPCodeGrantsAccess(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user with 2FA
	username := fmt.Sprintf("twofa_user_%d", time.Now().Unix())
	userID, totpSecret := createTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Create 2FA session
	ctx := context.Background()
	sessionToken, err := twoFATwoFASessionMgr.CreateTwoFASession(ctx, userID, username, "127.0.0.1", false, "database", nil)
	require.NoError(t, err)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/verify", twoFATestTwoFAHandler.TwoFAVerify)

	// Generate valid TOTP code
	validCode := generateValidTOTPCode(t, totpSecret)

	// Create verify request
	verifyReq := requests.TwoFAVerifyRequest{
		SessionToken: sessionToken,
		Code:         validCode,
	}
	body, _ := json.Marshal(verifyReq)

	// Make request
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response responses.TwoFAVerifyResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response.Success)
}

// T048: Integration test - Invalid TOTP code rejected
func TestTwoFAAuthFlow_InvalidTOTPCodeRejected(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user with 2FA
	username := fmt.Sprintf("twofa_user_%d", time.Now().Unix())
	userID, _ := createTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Create 2FA session
	ctx := context.Background()
	sessionToken, err := twoFATwoFASessionMgr.CreateTwoFASession(ctx, userID, username, "127.0.0.1", false, "database", nil)
	require.NoError(t, err)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/verify", twoFATestTwoFAHandler.TwoFAVerify)

	// Use invalid code
	invalidCode := "000000"

	// Create verify request
	verifyReq := requests.TwoFAVerifyRequest{
		SessionToken: sessionToken,
		Code:         invalidCode,
	}
	body, _ := json.Marshal(verifyReq)

	// Make request
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response responses.ErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "invalid_code", response.Error)
	assert.Contains(t, response.Details, "attempts_remaining")
	assert.Equal(t, float64(2), response.Details["attempts_remaining"]) // 2 attempts left
}

// T049: Integration test - 3 failed attempts trigger lockout
func TestTwoFAAuthFlow_MaxAttemptsTriggersLockout(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user with 2FA
	username := fmt.Sprintf("twofa_user_%d", time.Now().Unix())
	userID, _ := createTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Create 2FA session
	ctx := context.Background()
	sessionToken, err := twoFATwoFASessionMgr.CreateTwoFASession(ctx, userID, username, "127.0.0.1", false, "database", nil)
	require.NoError(t, err)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/verify", twoFATestTwoFAHandler.TwoFAVerify)

	invalidCode := "000000"

	// Attempt 1
	verifyReq := requests.TwoFAVerifyRequest{
		SessionToken: sessionToken,
		Code:         invalidCode,
	}
	body, _ := json.Marshal(verifyReq)
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Attempt 2
	body, _ = json.Marshal(verifyReq)
	req = httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Attempt 3 - should trigger lockout
	body, _ = json.Marshal(verifyReq)
	req = httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert lockout response
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	var response responses.ErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "max_attempts_exceeded", response.Error)
	assert.Contains(t, response.ErrorDescription, "locked")

	// Verify account is locked
	isLocked, err := twoFATwoFASessionMgr.IsAccountLocked(ctx, userID)
	require.NoError(t, err)
	assert.True(t, isLocked)
}

// T050: Integration test - 2FA session expires after timeout
func TestTwoFAAuthFlow_SessionExpiresAfterTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user with 2FA
	username := fmt.Sprintf("twofa_user_%d", time.Now().Unix())
	userID, totpSecret := createTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Create 2FA session with short timeout for testing
	ctx := context.Background()

	// Temporarily modify config for faster testing
	originalTimeout := twoFATestConfig.TwoFactor.SessionTimeout
	twoFATestConfig.TwoFactor.SessionTimeout = 2 // 2 seconds
	defer func() {
		twoFATestConfig.TwoFactor.SessionTimeout = originalTimeout
	}()

	sessionToken, err := twoFATwoFASessionMgr.CreateTwoFASession(ctx, userID, username, "127.0.0.1", false, "database", nil)
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(3 * time.Second)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/verify", twoFATestTwoFAHandler.TwoFAVerify)

	// Try to verify with valid code after expiration
	validCode := generateValidTOTPCode(t, totpSecret)
	verifyReq := requests.TwoFAVerifyRequest{
		SessionToken: sessionToken,
		Code:         validCode,
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert session expired
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response responses.ErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "invalid_session", response.Error)
	assert.Contains(t, response.ErrorDescription, "expired")
}

// T051: Integration test - Valid backup code grants access
func TestTwoFAAuthFlow_BackupCodeGrantsAccess(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user with 2FA
	username := fmt.Sprintf("twofa_user_%d", time.Now().Unix())
	userID, _ := createTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Generate backup codes
	ctx := context.Background()
	backupCodes, err := twoFATestDB.GenerateBackupCodes(ctx, userID, 10)
	require.NoError(t, err)
	require.Len(t, backupCodes, 10)

	// Create 2FA session
	sessionToken, err := twoFATwoFASessionMgr.CreateTwoFASession(ctx, userID, username, "127.0.0.1", false, "database", nil)
	require.NoError(t, err)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/verify", twoFATestTwoFAHandler.TwoFAVerify)

	// Use first backup code
	backupCode := backupCodes[0]

	verifyReq := requests.TwoFAVerifyRequest{
		SessionToken: sessionToken,
		Code:         backupCode,
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert success
	assert.Equal(t, http.StatusOK, w.Code)

	var response responses.TwoFAVerifyResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response.Success)

	// Verify backup code was consumed (cannot use again)
	sessionToken2, err := twoFATwoFASessionMgr.CreateTwoFASession(ctx, userID, username, "127.0.0.1", false, "database", nil)
	require.NoError(t, err)

	verifyReq.SessionToken = sessionToken2
	body, _ = json.Marshal(verifyReq)

	req = httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should fail - backup code already used
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// T083: Integration test - Invalid backup code rejected
func TestTwoFAAuthFlow_InvalidBackupCodeRejected(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user with 2FA
	username := fmt.Sprintf("twofa_user_%d", time.Now().Unix())
	userID, _ := createTestUserWith2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Create 2FA session
	ctx := context.Background()
	sessionToken, err := twoFATwoFASessionMgr.CreateTwoFASession(ctx, userID, username, "127.0.0.1", false, "database", nil)
	require.NoError(t, err)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/verify", twoFATestTwoFAHandler.TwoFAVerify)

	// Use invalid backup code (wrong format/length)
	invalidBackupCode := "INVALIDCODE"

	verifyReq := requests.TwoFAVerifyRequest{
		SessionToken: sessionToken,
		Code:         invalidBackupCode,
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert rejection
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response responses.ErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "invalid_code", response.Error)
	assert.Contains(t, response.Details, "attempts_remaining")
	assert.Equal(t, float64(2), response.Details["attempts_remaining"]) // 2 attempts left
}
