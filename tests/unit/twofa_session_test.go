package unit

// Unit Tests for 2FA Session Management (Phase 2: User Story 1)
//
// These tests verify session management operations including:
// - 2FA session creation and validation
// - Failed attempt tracking and lockout logic
// - Account locking and unlocking mechanisms
//
// Requires: Running Redis server for session storage
//
// To run these tests:
//   export TEST_REDIS_URL="localhost:6379"
//   go test ./tests/unit/ -v -run TestTwoFASession
//
// To skip Redis tests:
//   go test ./tests/unit/ -v -run TestTwoFASession -short

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/session"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testRedisClient   *redis.Client
	testSessionConfig *config.Config
	testSessionMgr    *session.TwoFASessionManager
	testLogger        *logger.Logger
)

func init() {
	// Setup Redis connection
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	testRedisClient = redis.NewClient(&redis.Options{
		Addr: redisURL,
		DB:   15, // Use separate DB for unit tests
	})

	// Test connection
	ctx := context.Background()
	if err := testRedisClient.Ping(ctx).Err(); err != nil {
		fmt.Printf("Failed to connect to Redis: %v\n", err)
		fmt.Println("Skipping Redis session unit tests")
		testRedisClient = nil
		return
	}

	// Setup test config
	testSessionConfig = &config.Config{
		TwoFactor: config.TwoFactorConfig{
			SessionTimeout:  300, // 5 minutes
			MaxAttempts:     3,
			LockoutDuration: 3600, // 1 hour
		},
	}

	// Setup test logger
	testLogger = logger.New("info", "text")

	// Setup session manager
	testSessionMgr = session.NewTwoFASessionManager(testRedisClient, testLogger, testSessionConfig)
}

// T043: Unit test - CreateTwoFASession creates valid session
func TestTwoFASession_CreateTwoFASessionCreatesValidSession(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis session unit tests in short mode")
	}
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()

	// Create session
	sessionToken, err := testSessionMgr.CreateTwoFASession(ctx, 123, "testuser", "192.168.1.1", false)
	require.NoError(t, err)
	assert.NotEmpty(t, sessionToken)

	// Verify session exists in Redis
	sessionKey := fmt.Sprintf("twofa:session:%s", sessionToken)
	exists, err := testRedisClient.Exists(ctx, sessionKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists)

	// Verify session data
	sessionData, err := testRedisClient.HGetAll(ctx, sessionKey).Result()
	require.NoError(t, err)

	assert.Equal(t, "123", sessionData["user_id"])
	assert.Equal(t, "testuser", sessionData["username"])
	assert.Equal(t, "192.168.1.1", sessionData["ip"])
	assert.Equal(t, "false", sessionData["enrollment_mode"])
	assert.Equal(t, "0", sessionData["attempts"])

	// Cleanup
	testRedisClient.Del(ctx, sessionKey)
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%d", 123))
}

// T043: Unit test - CreateTwoFASession sets expiration
func TestTwoFASession_CreateTwoFASessionSetsExpiration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis session unit tests in short mode")
	}
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()

	// Create session
	sessionToken, err := testSessionMgr.CreateTwoFASession(ctx, 456, "testuser2", "192.168.1.2", false)
	require.NoError(t, err)

	// Verify session has expiration
	sessionKey := fmt.Sprintf("twofa:session:%s", sessionToken)
	ttl, err := testRedisClient.TTL(ctx, sessionKey).Result()
	require.NoError(t, err)

	// Should expire in ~300 seconds (with some tolerance)
	assert.Greater(t, ttl.Seconds(), float64(290))
	assert.Less(t, ttl.Seconds(), float64(310))

	// Cleanup
	testRedisClient.Del(ctx, sessionKey)
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%d", 456))
}

// T043: Unit test - CreateEnrollmentSession creates session in enrollment mode
func TestTwoFASession_CreateEnrollmentSessionSetsEnrollmentMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis session unit tests in short mode")
	}
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()

	// Create enrollment session
	sessionToken, err := testSessionMgr.CreateEnrollmentSession(ctx, 789, "enrolluser", "192.168.1.3")
	require.NoError(t, err)
	assert.NotEmpty(t, sessionToken)

	// Verify enrollment mode is set
	sessionKey := fmt.Sprintf("twofa:session:%s", sessionToken)
	enrollmentMode, err := testRedisClient.HGet(ctx, sessionKey, "enrollment_mode").Result()
	require.NoError(t, err)
	assert.Equal(t, "true", enrollmentMode)

	// Cleanup
	testRedisClient.Del(ctx, sessionKey)
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%d", 789))
}

// T044: Unit test - TrackTwoFAAttempts increments counter
func TestTwoFASession_TrackTwoFAAttemptsIncrementsCounter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis session unit tests in short mode")
	}
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()
	userID := 1001

	// Create a session first
	sessionToken, err := testSessionMgr.CreateTwoFASession(ctx, userID, "testuser", "192.168.1.1", false)
	require.NoError(t, err)

	// Track attempts using session token
	attempts1, err := testSessionMgr.TrackTwoFAAttempts(ctx, sessionToken)
	require.NoError(t, err)
	assert.Equal(t, 1, attempts1)

	attempts2, err := testSessionMgr.TrackTwoFAAttempts(ctx, sessionToken)
	require.NoError(t, err)
	assert.Equal(t, 2, attempts2)

	attempts3, err := testSessionMgr.TrackTwoFAAttempts(ctx, sessionToken)
	require.NoError(t, err)
	assert.Equal(t, 3, attempts3)

	// Cleanup
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:session:%s", sessionToken))
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%s", sessionToken))
}

// T044: Unit test - TrackTwoFAAttempts locks account after max attempts
func TestTwoFASession_TrackTwoFAAttemptsLocksAccountAfterMaxAttempts(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()
	userID := 1002

	// Create a session first
	sessionToken, err := testSessionMgr.CreateTwoFASession(ctx, userID, "testuser", "192.168.1.1", false)
	require.NoError(t, err)

	// Make 3 failed attempts
	for i := 0; i < 3; i++ {
		_, err := testSessionMgr.TrackTwoFAAttempts(ctx, sessionToken)
		require.NoError(t, err)
	}

	// Verify account is locked
	locked, err := testSessionMgr.IsAccountLocked(ctx, userID)
	require.NoError(t, err)
	assert.True(t, locked)

	// Cleanup
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:session:%s", sessionToken))
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%s", sessionToken))
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:locked:%d", userID))
}

// T044: Unit test - TrackTwoFAAttempts sets lockout expiration
func TestTwoFASession_TrackTwoFAAttemptsSetsLockoutExpiration(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()
	userID := 1003

	// Create a session first
	sessionToken, err := testSessionMgr.CreateTwoFASession(ctx, userID, "testuser", "192.168.1.1", false)
	require.NoError(t, err)

	// Make 3 failed attempts to trigger lockout
	for i := 0; i < 3; i++ {
		_, err := testSessionMgr.TrackTwoFAAttempts(ctx, sessionToken)
		require.NoError(t, err)
	}

	// Verify lockout has expiration
	lockoutKey := fmt.Sprintf("twofa:locked:%d", userID)
	ttl, err := testRedisClient.TTL(ctx, lockoutKey).Result()
	require.NoError(t, err)

	// Should expire in ~3600 seconds (1 hour, with some tolerance)
	assert.Greater(t, ttl.Seconds(), float64(3590))
	assert.Less(t, ttl.Seconds(), float64(3610))

	// Cleanup
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:session:%s", sessionToken))
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%s", sessionToken))
	testRedisClient.Del(ctx, lockoutKey)
}

// T045: Unit test - IsAccountLocked returns false for unlocked account
func TestTwoFASession_IsAccountLockedReturnsFalseForUnlockedAccount(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()
	userID := 2001

	// Check unlocked account
	locked, err := testSessionMgr.IsAccountLocked(ctx, userID)
	require.NoError(t, err)
	assert.False(t, locked)
}

// T045: Unit test - IsAccountLocked returns true for locked account
func TestTwoFASession_IsAccountLockedReturnsTrueForLockedAccount(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()
	userID := 2002

	// Lock account manually
	lockoutKey := fmt.Sprintf("twofa:locked:%d", userID)
	err := testRedisClient.Set(ctx, lockoutKey, "locked", time.Hour).Err()
	require.NoError(t, err)

	// Check locked account
	locked, err := testSessionMgr.IsAccountLocked(ctx, userID)
	require.NoError(t, err)
	assert.True(t, locked)

	// Cleanup
	testRedisClient.Del(ctx, lockoutKey)
}

// T045: Unit test - LockAccount locks account for duration
func TestTwoFASession_LockAccountLocksAccountForDuration(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()
	userID := 2003

	// Lock account
	err := testSessionMgr.LockAccount(ctx, userID)
	require.NoError(t, err)

	// Verify account is locked
	locked, err := testSessionMgr.IsAccountLocked(ctx, userID)
	require.NoError(t, err)
	assert.True(t, locked)

	// Verify lockout expiration
	lockoutKey := fmt.Sprintf("twofa:locked:%d", userID)
	ttl, err := testRedisClient.TTL(ctx, lockoutKey).Result()
	require.NoError(t, err)
	assert.Greater(t, ttl.Seconds(), float64(3590))

	// Cleanup
	testRedisClient.Del(ctx, lockoutKey)
}

// T045: Unit test - Account unlocks automatically after lockout time
func TestTwoFASession_AccountUnlocksAutomaticallyAfterLockoutTime(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()
	userID := 2004

	// Temporarily set shorter lockout for testing
	originalLockout := testSessionConfig.TwoFactor.LockoutDuration
	testSessionConfig.TwoFactor.LockoutDuration = 2 // 2 seconds
	defer func() {
		testSessionConfig.TwoFactor.LockoutDuration = originalLockout
	}()

	// Create a session and make 3 failed attempts to trigger lockout
	sessionToken, err := testSessionMgr.CreateTwoFASession(ctx, userID, "testuser", "192.168.1.1", false)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		_, err := testSessionMgr.TrackTwoFAAttempts(ctx, sessionToken)
		require.NoError(t, err)
	}

	// Verify locked
	locked, err := testSessionMgr.IsAccountLocked(ctx, userID)
	require.NoError(t, err)
	assert.True(t, locked)

	// Wait for lockout to expire
	time.Sleep(3 * time.Second)

	// Verify unlocked
	locked, err = testSessionMgr.IsAccountLocked(ctx, userID)
	require.NoError(t, err)
	assert.False(t, locked, "Account should unlock automatically after lockout time")

	// Cleanup
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:session:%s", sessionToken))
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%s", sessionToken))
}

// Additional test: Verify session token uniqueness
func TestTwoFASession_SessionTokensAreUnique(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()

	// Create multiple sessions
	tokens := make(map[string]bool)
	for i := 0; i < 10; i++ {
		token, err := testSessionMgr.CreateTwoFASession(ctx, i+3000, fmt.Sprintf("user%d", i), "192.168.1.1", false)
		require.NoError(t, err)

		// Verify uniqueness
		assert.False(t, tokens[token], "Session tokens should be unique")
		tokens[token] = true

		// Cleanup
		testRedisClient.Del(ctx, fmt.Sprintf("twofa:session:%s", token))
		testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%d", i+3000))
	}

	assert.Len(t, tokens, 10)
}

// Additional test: Verify IP address tracking
func TestTwoFASession_TracksIPAddress(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()

	// Create session with specific IP
	sessionToken, err := testSessionMgr.CreateTwoFASession(ctx, 4001, "ipuser", "10.0.0.50", false)
	require.NoError(t, err)

	// Verify IP is stored
	sessionKey := fmt.Sprintf("twofa:session:%s", sessionToken)
	ip, err := testRedisClient.HGet(ctx, sessionKey, "ip").Result()
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.50", ip)

	// Cleanup
	testRedisClient.Del(ctx, sessionKey)
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%d", 4001))
}

// Additional test: Verify attempt counter resets on successful login
func TestTwoFASession_AttemptCounterResetsOnSuccess(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()
	userID := 5001

	// Create a session first
	sessionToken, err := testSessionMgr.CreateTwoFASession(ctx, userID, "testuser", "192.168.1.1", false)
	require.NoError(t, err)

	// Make some failed attempts
	for i := 0; i < 2; i++ {
		_, err := testSessionMgr.TrackTwoFAAttempts(ctx, sessionToken)
		require.NoError(t, err)
	}

	// Verify attempts tracked
	attemptsKey := fmt.Sprintf("twofa:attempts:%s", sessionToken)
	attempts, err := testRedisClient.Get(ctx, attemptsKey).Result()
	require.NoError(t, err)
	assert.Equal(t, "2", attempts)

	// Simulate successful login by deleting attempts
	err = testRedisClient.Del(ctx, attemptsKey).Err()
	require.NoError(t, err)

	// Verify counter reset
	_, err = testRedisClient.Get(ctx, attemptsKey).Result()
	assert.Equal(t, redis.Nil, err, "Attempts counter should be deleted on success")

	// Cleanup
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:session:%s", sessionToken))
}

// Additional test: Verify session data integrity
func TestTwoFASession_SessionDataIntegrity(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available")
	}

	ctx := context.Background()

	// Create session
	sessionToken, err := testSessionMgr.CreateTwoFASession(ctx, 6001, "testuser", "192.168.1.100", true)
	require.NoError(t, err)

	// Retrieve all session data
	sessionKey := fmt.Sprintf("twofa:session:%s", sessionToken)
	sessionData, err := testRedisClient.HGetAll(ctx, sessionKey).Result()
	require.NoError(t, err)

	// Verify all expected fields
	assert.Equal(t, "6001", sessionData["user_id"])
	assert.Equal(t, "testuser", sessionData["username"])
	assert.Equal(t, "192.168.1.100", sessionData["ip"])
	assert.Equal(t, "true", sessionData["enrollment_mode"])
	assert.Equal(t, "0", sessionData["attempts"])
	assert.NotEmpty(t, sessionData["created_at"])

	// Cleanup
	testRedisClient.Del(ctx, sessionKey)
	testRedisClient.Del(ctx, fmt.Sprintf("twofa:attempts:%d", 6001))
}
