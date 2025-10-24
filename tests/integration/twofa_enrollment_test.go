package integration

// Integration Tests for 2FA Enrollment Flow (Phase 4: User Story 2)
//
// These tests verify the complete 2FA enrollment process including:
// - QR code generation and secret distribution
// - Enrollment confirmation with valid TOTP code
// - Backup codes generation upon successful enrollment
// - Enrollment requirement detection and redirection
// - Enrollment session timeout
//
// Prerequisites:
// 1. PostgreSQL database with Redmine schema
// 2. Redis server for session management
// 3. Test users without 2FA configured
//
// To run these tests:
//   export TEST_DATABASE_URL="postgres://postgres:test@localhost:5432/redmine?sslmode=disable"
//   export TEST_REDIS_URL="localhost:6379"
//   go test ./tests/integration/ -v -run TestTwoFAEnrollment
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
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-make-bytes/redmine-gateway/internal/router/requests"
	"github.com/go-make-bytes/redmine-gateway/internal/router/responses"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a test user WITHOUT 2FA
func createTestUserWithout2FA(t *testing.T, username string) (userID int) {
	ctx := context.Background()

	// Generate proper Redmine-style password hash
	password := "password"
	salt := generateRandomString(32) // Generate a random salt
	hashedPassword := hashRedminePassword(password, salt)

	// Create test user in database
	query := `
		INSERT INTO users (login, hashed_password, salt, firstname, lastname, created_on, updated_on, status, type)
		VALUES ($1, $2, $3, 'Test', 'User', NOW(), NOW(), 1, 'User')
		RETURNING id
	`
	err := twoFATestDB.QueryRowContext(ctx, query, username, hashedPassword, salt).Scan(&userID)
	require.NoError(t, err)

	// Create email address entry
	email := username + "@test.com"
	_, err = twoFATestDB.ExecContext(ctx, `
		INSERT INTO email_addresses (user_id, address, is_default, notify, created_on, updated_on)
		VALUES ($1, $2, true, true, NOW(), NOW())
	`, userID, email)
	require.NoError(t, err)

	return userID
}

// T063: Integration test - Setup returns QR code and secret
func TestTwoFAEnrollment_SetupReturnsQRCodeAndSecret(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user without 2FA
	username := fmt.Sprintf("enroll_user_%d", time.Now().Unix())
	userID := createTestUserWithout2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Create enrollment session
	ctx := context.Background()
	sessionToken, err := twoFATwoFASessionMgr.CreateEnrollmentSession(ctx, userID, username, "127.0.0.1")
	require.NoError(t, err)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/2fa/setup", twoFATestTwoFAHandler.TwoFASetup)

	// Make request
	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/setup?token="+sessionToken, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response responses.TwoFASetupResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Verify QR code and secret
	assert.NotEmpty(t, response.Secret)
	assert.NotEmpty(t, response.QRCodeURL)
	assert.Contains(t, response.QRCodeURL, "data:image/png;base64,")
	assert.Equal(t, "Redmine Gateway Test", response.Issuer)
	assert.Equal(t, username, response.Account)

	// Verify secret is valid Base32
	assert.Len(t, response.Secret, 32) // TOTP secrets are typically 32 characters in Base32
}

// T064: Integration test - Confirm with valid code enables 2FA
func TestTwoFAEnrollment_ConfirmWithValidCodeEnables2FA(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user without 2FA
	username := fmt.Sprintf("enroll_user_%d", time.Now().Unix())
	userID := createTestUserWithout2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Create enrollment session
	ctx := context.Background()
	sessionToken, err := twoFATwoFASessionMgr.CreateEnrollmentSession(ctx, userID, username, "127.0.0.1")
	require.NoError(t, err)

	// Setup router for setup
	gin.SetMode(gin.TestMode)
	setupRouter := gin.New()
	setupRouter.GET("/auth/2fa/setup", twoFATestTwoFAHandler.TwoFASetup)

	// Get secret
	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/setup?token="+sessionToken, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	setupRouter.ServeHTTP(w, req)

	var setupResponse responses.TwoFASetupResponse
	err = json.Unmarshal(w.Body.Bytes(), &setupResponse)
	require.NoError(t, err)

	// Generate valid TOTP code from secret
	validCode, err := totp.GenerateCode(setupResponse.Secret, time.Now())
	require.NoError(t, err)

	// Setup confirm router
	confirmRouter := gin.New()
	confirmRouter.POST("/auth/2fa/confirm", twoFATestTwoFAHandler.TwoFAConfirm)

	// Confirm enrollment
	confirmReq := requests.TwoFAConfirmRequest{
		Code:   validCode,
		Secret: setupResponse.Secret,
	}
	body, _ := json.Marshal(confirmReq)

	req = httptest.NewRequest(http.MethodPost, "/auth/2fa/confirm", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-2FA-Session-Token", sessionToken)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	confirmRouter.ServeHTTP(w, req)

	// Assert success
	assert.Equal(t, http.StatusOK, w.Code)

	var confirmResponse responses.TwoFAConfirmResponse
	err = json.Unmarshal(w.Body.Bytes(), &confirmResponse)
	require.NoError(t, err)

	assert.True(t, confirmResponse.Success)

	// Verify 2FA is enabled in database
	twoFARequired, err := twoFATestDB.IsTwoFactorRequired(ctx, userID)
	require.NoError(t, err)
	assert.True(t, twoFARequired)
}

// T065: Integration test - Confirm generates 10 backup codes
func TestTwoFAEnrollment_ConfirmGeneratesBackupCodes(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user without 2FA
	username := fmt.Sprintf("enroll_user_%d", time.Now().Unix())
	userID := createTestUserWithout2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Create enrollment session
	ctx := context.Background()
	sessionToken, err := twoFATwoFASessionMgr.CreateEnrollmentSession(ctx, userID, username, "127.0.0.1")
	require.NoError(t, err)

	// Setup router for setup
	gin.SetMode(gin.TestMode)
	setupRouter := gin.New()
	setupRouter.GET("/auth/2fa/setup", twoFATestTwoFAHandler.TwoFASetup)

	// Get secret
	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/setup?token="+sessionToken, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	setupRouter.ServeHTTP(w, req)

	var setupResponse responses.TwoFASetupResponse
	err = json.Unmarshal(w.Body.Bytes(), &setupResponse)
	require.NoError(t, err)

	// Generate valid TOTP code
	validCode, err := totp.GenerateCode(setupResponse.Secret, time.Now())
	require.NoError(t, err)

	// Setup confirm router
	confirmRouter := gin.New()
	confirmRouter.POST("/auth/2fa/confirm", twoFATestTwoFAHandler.TwoFAConfirm)

	// Confirm enrollment
	confirmReq := requests.TwoFAConfirmRequest{
		Code:   validCode,
		Secret: setupResponse.Secret,
	}
	body, _ := json.Marshal(confirmReq)

	req = httptest.NewRequest(http.MethodPost, "/auth/2fa/confirm", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-2FA-Session-Token", sessionToken)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	confirmRouter.ServeHTTP(w, req)

	// Assert success
	assert.Equal(t, http.StatusOK, w.Code)

	var confirmResponse responses.TwoFAConfirmResponse
	err = json.Unmarshal(w.Body.Bytes(), &confirmResponse)
	require.NoError(t, err)

	assert.True(t, confirmResponse.Success)

	// Verify backup codes
	assert.Len(t, confirmResponse.BackupCodes, 10)

	// Verify each backup code is valid format (8 characters, alphanumeric)
	for _, code := range confirmResponse.BackupCodes {
		assert.Len(t, code, 8)
		assert.Regexp(t, "^[A-Z0-9]+$", code)
	}

	// Verify backup codes are stored in database
	var backupCodeCount int
	err = twoFATestDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code'", userID).Scan(&backupCodeCount)
	require.NoError(t, err)
	assert.Equal(t, 10, backupCodeCount)
}

// T066: Integration test - Required 2FA redirects to enrollment
func TestTwoFAEnrollment_RequiredRedirectsToEnrollment(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user without 2FA
	username := fmt.Sprintf("enroll_user_%d", time.Now().Unix())
	userID := createTestUserWithout2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Mark user as requiring 2FA (by updating tfa field to some value that indicates requirement)
	// In Redmine, users can be required to have 2FA. This simulates that requirement.
	// Note: Actual implementation may vary based on your schema
	ctx := context.Background()
	twoFATestDB.ExecContext(ctx, "UPDATE users SET tfa = 'required' WHERE id = $1", userID)

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

	// Assert response indicates enrollment is needed
	assert.Equal(t, http.StatusOK, w.Code)

	var response responses.TwoFAChallengeResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response.RequiresTwoFA)
	assert.True(t, response.EnrollmentMode) // Should be in enrollment mode
	assert.NotEmpty(t, response.SessionToken)
}

// T067: Integration test - Enrollment session expires after timeout
func TestTwoFAEnrollment_SessionExpiresAfterTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user without 2FA
	username := fmt.Sprintf("enroll_user_%d", time.Now().Unix())
	userID := createTestUserWithout2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Temporarily modify config for faster testing
	ctx := context.Background()
	originalTimeout := twoFATestConfig.TwoFactor.SessionTimeout
	twoFATestConfig.TwoFactor.SessionTimeout = 2 // 2 seconds
	defer func() {
		twoFATestConfig.TwoFactor.SessionTimeout = originalTimeout
	}()

	// Create enrollment session with short timeout
	sessionToken, err := twoFATwoFASessionMgr.CreateEnrollmentSession(ctx, userID, username, "127.0.0.1")
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(3 * time.Second)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/2fa/setup", twoFATestTwoFAHandler.TwoFASetup)

	// Try to access setup after expiration
	req := httptest.NewRequest(http.MethodGet, "/auth/2fa/setup?token="+sessionToken, nil)
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

// Additional test: Verify enrollment session can't be used for verification
func TestTwoFAEnrollment_EnrollmentSessionCannotBeUsedForVerification(t *testing.T) {
	setupTwoFATestEnvironment(t)
	defer teardownTwoFATestEnvironment()

	// Create test user without 2FA
	username := fmt.Sprintf("enroll_user_%d", time.Now().Unix())
	userID := createTestUserWithout2FA(t, username)
	defer func() {
		ctx := context.Background()
		twoFATestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		twoFATestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Create enrollment session
	ctx := context.Background()
	sessionToken, err := twoFATwoFASessionMgr.CreateEnrollmentSession(ctx, userID, username, "127.0.0.1")
	require.NoError(t, err)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/2fa/verify", twoFATestTwoFAHandler.TwoFAVerify)

	// Try to use enrollment session for verification
	verifyReq := requests.TwoFAVerifyRequest{
		SessionToken: sessionToken,
		Code:         "123456",
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should fail - enrollment session can't be used for verification
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response responses.ErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "not_verification_mode", response.Error)
}
