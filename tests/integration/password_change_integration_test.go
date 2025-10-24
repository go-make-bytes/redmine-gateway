package integration

// Integration Tests for Password Change Flow
//
// These tests verify the complete password change flow including:
// - Password change requirement detection during login
// - Password change page access
// - Password change validation and execution
// - Security token cleanup after password change
//
// Prerequisites:
// 1. PostgreSQL database with Redmine schema
// 2. Redis server for session management
// 3. Test users with must_change_password flag set
//
// To run these tests:
//   export TEST_DATABASE_URL="postgres://postgres:test@localhost:5432/redmine?sslmode=disable"
//   export TEST_REDIS_URL="localhost:6379"
//   go test ./tests/integration/ -v -run TestPasswordChange
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
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/handlers"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/middleware"
	"github.com/go-make-bytes/redmine-gateway/internal/router/requests"
	"github.com/go-make-bytes/redmine-gateway/internal/router/responses"
	"github.com/go-make-bytes/redmine-gateway/internal/session"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures for password change
var (
	passwordTestDB          *database.PostgreSQL
	passwordTestRedis       *redis.Client
	passwordTestLogger      *logger.Logger
	passwordTestConfig      *config.Config
	passwordTestAuthHandler *handlers.AuthHandler
	passwordTestSessionMgr  *session.SessionManager
)

func setupPasswordTestEnvironment(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration tests: SKIP_INTEGRATION_TESTS=true")
	}

	// Setup test database
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:test@localhost:5432/redmine?sslmode=disable"
	}

	var err error
	passwordTestDB, err = database.NewPostgreSQL(dbURL)
	if err != nil {
		t.Skipf("Skipping integration tests: Failed to connect to test database: %v", err)
	}

	// Setup test Redis
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	passwordTestRedis = redis.NewClient(&redis.Options{
		Addr: redisURL,
		DB:   16, // Use database 16 for password change testing
	})

	ctx := context.Background()
	if err := passwordTestRedis.Ping(ctx).Err(); err != nil {
		t.Skipf("Skipping integration tests: Failed to connect to Redis: %v", err)
	}

	// Clear test Redis database
	passwordTestRedis.FlushDB(ctx)

	// Setup test logger
	passwordTestLogger = logger.New("error", "json")

	// Setup test config
	passwordTestConfig = &config.Config{
		TwoFactor: config.TwoFactorConfig{
			Enabled: false, // Disable 2FA for password change tests
		},
		Redmine: config.RedmineConfig{
			SecretKeyBase: "test-secret-key-base-for-encryption-must-be-32-chars-long",
		},
	}

	// Initialize components
	passwordTestSessionMgr = session.NewSessionManager(passwordTestRedis, passwordTestLogger, 900)

	inputValidator := middleware.NewInputValidator(50, 100)
	csrfProtection := middleware.NewCSRFProtection(passwordTestRedis, passwordTestLogger, "test-csrf-secret")

	// Create a mock 2FA session manager (not used in these tests)
	mockTwoFASessionMgr := session.NewTwoFASessionManager(passwordTestRedis, passwordTestLogger, passwordTestConfig)

	passwordTestAuthHandler = handlers.NewAuthHandler(
		passwordTestConfig,
		passwordTestDB,
		passwordTestLogger,
		passwordTestSessionMgr,
		mockTwoFASessionMgr,
		inputValidator,
		csrfProtection,
	)
}

func teardownPasswordTestEnvironment() {
	if passwordTestDB != nil {
		passwordTestDB.Close()
	}
	if passwordTestRedis != nil {
		ctx := context.Background()
		passwordTestRedis.FlushDB(ctx)
		passwordTestRedis.Close()
	}
}

// Helper function to create a test user requiring password change
func createTestUserRequiringPasswordChange(t *testing.T, username string) int {
	ctx := context.Background()

	// Create test user with must_change_password = true
	var userID int
	err := passwordTestDB.QueryRowContext(ctx, `
		INSERT INTO users (login, hashed_password, salt, firstname, lastname, created_on, updated_on, status, type, must_change_passwd)
		VALUES ($1, 'dummy_hash', 'dummy_salt', 'Test', 'User', NOW(), NOW(), 1, 'User', true)
		RETURNING id
	`, username).Scan(&userID)
	require.NoError(t, err)

	// Create email address entry
	email := username + "@test.com"
	_, err = passwordTestDB.ExecContext(ctx, `
		INSERT INTO email_addresses (user_id, address, is_default, notify, created_on, updated_on)
		VALUES ($1, $2, true, true, NOW(), NOW())
	`, userID, email)
	require.NoError(t, err)

	return userID
}

// T052: Integration test - Login with user requiring password change returns password change required
func TestPasswordChangeFlow_LoginReturnsPasswordChangeRequired(t *testing.T) {
	setupPasswordTestEnvironment(t)
	defer teardownPasswordTestEnvironment()

	// Create test user requiring password change
	username := fmt.Sprintf("pwd_change_user_%d", time.Now().Unix())
	userID := createTestUserRequiringPasswordChange(t, username)
	defer func() {
		// Cleanup: delete test user
		ctx := context.Background()
		passwordTestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		passwordTestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", passwordTestAuthHandler.Login)

	// Create login request
	loginReq := requests.AuthRequest{
		Username: username,
		Password: "dummy_password", // Won't match but that's ok for this test
	}
	body, _ := json.Marshal(loginReq)

	// Make request
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response responses.PasswordChangeRequiredResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response.RequiresPasswordChange)
	assert.Equal(t, userID, response.UserID)
	assert.Contains(t, response.Message, "Password change is required")
}

// T053: Integration test - Password change page accessible for valid user
func TestPasswordChangeFlow_PasswordChangePageAccessible(t *testing.T) {
	setupPasswordTestEnvironment(t)
	defer teardownPasswordTestEnvironment()

	// Create test user requiring password change
	username := fmt.Sprintf("pwd_change_user_%d", time.Now().Unix())
	userID := createTestUserRequiringPasswordChange(t, username)
	defer func() {
		// Cleanup: delete test user
		ctx := context.Background()
		passwordTestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		passwordTestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/password/change", passwordTestAuthHandler.ShowPasswordChangePage)

	// Make request to password change page
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/password/change?user_id=%d", userID), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Change Password")
	assert.Contains(t, w.Body.String(), "password_change.html")
}

// T054: Integration test - Password change page rejects invalid user ID
func TestPasswordChangeFlow_PasswordChangePageRejectsInvalidUser(t *testing.T) {
	setupPasswordTestEnvironment(t)
	defer teardownPasswordTestEnvironment()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/password/change", passwordTestAuthHandler.ShowPasswordChangePage)

	// Make request with invalid user ID
	req := httptest.NewRequest(http.MethodGet, "/auth/password/change?user_id=99999", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusNotFound, w.Code)

	var response responses.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "user_not_found", response.Error)
}

// T055: Integration test - Password change page rejects user not requiring change
func TestPasswordChangeFlow_PasswordChangePageRejectsUserNotRequiringChange(t *testing.T) {
	setupPasswordTestEnvironment(t)
	defer teardownPasswordTestEnvironment()

	// Create test user NOT requiring password change
	username := fmt.Sprintf("normal_user_%d", time.Now().Unix())
	ctx := context.Background()
	var userID int
	err := passwordTestDB.QueryRowContext(ctx, `
		INSERT INTO users (login, hashed_password, salt, firstname, lastname, created_on, updated_on, status, type, must_change_passwd)
		VALUES ($1, 'dummy_hash', 'dummy_salt', 'Test', 'User', NOW(), NOW(), 1, 'User', false)
		RETURNING id
	`, username).Scan(&userID)
	require.NoError(t, err)

	defer func() {
		// Cleanup: delete test user
		passwordTestDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID)
		passwordTestDB.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = $1", userID)
	}()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/password/change", passwordTestAuthHandler.ShowPasswordChangePage)

	// Make request to password change page
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/password/change?user_id=%d", userID), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response responses.ErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "password_change_not_required", response.Error)
}
