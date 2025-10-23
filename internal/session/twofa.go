package session

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// TwoFASessionManager handles 2FA session management
type TwoFASessionManager struct {
	redis  *redis.Client
	logger *logger.Logger
	config *config.Config
}

// TwoFASessionData represents temporary 2FA session data
type TwoFASessionData struct {
	UserID         int       `json:"user_id"`
	Username       string    `json:"username"`
	IP             string    `json:"ip"`
	Attempts       int       `json:"attempts"`
	CreatedAt      time.Time `json:"created_at"`
	EnrollmentMode bool      `json:"enrollment_mode,omitempty"`
}

// NewTwoFASessionManager creates a new 2FA session manager
func NewTwoFASessionManager(redis *redis.Client, logger *logger.Logger, cfg *config.Config) *TwoFASessionManager {
	return &TwoFASessionManager{
		redis:  redis,
		logger: logger,
		config: cfg,
	}
}

// CreateTwoFASession creates a new temporary 2FA session with 5 minutes timeout
func (m *TwoFASessionManager) CreateTwoFASession(ctx context.Context, userID int, username, ip string, enrollmentMode bool) (string, error) {
	// Generate UUID v4 token
	token := uuid.New().String()

	// Create session data
	sessionData := &TwoFASessionData{
		UserID:         userID,
		Username:       username,
		IP:             ip,
		Attempts:       0,
		CreatedAt:      time.Now(),
		EnrollmentMode: enrollmentMode,
	}

	// Serialize to JSON
	data, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal 2FA session data: %w", err)
	}

	// Store in Redis with TTL
	key := fmt.Sprintf("twofa:session:%s", token)
	ttl := time.Duration(m.config.TwoFactor.SessionTimeout) * time.Second
	if err := m.redis.Set(ctx, key, data, ttl).Err(); err != nil {
		return "", fmt.Errorf("failed to create 2FA session: %w", err)
	}

	// Log session creation
	eventType := "twofa_verification_session_created"
	if enrollmentMode {
		eventType = "twofa_enrollment_session_created"
	}

	m.logger.Info("Created 2FA session",
		"event", eventType,
		"user_id", userID,
		"username", username,
		"enrollment_mode", enrollmentMode,
		"ip", ip,
		"ttl_seconds", m.config.TwoFactor.SessionTimeout,
		"timestamp", time.Now().Unix(),
	)

	return token, nil
}

// CreateEnrollmentSession creates a new 2FA enrollment session
// This is a convenience wrapper for CreateTwoFASession with enrollment mode enabled
func (m *TwoFASessionManager) CreateEnrollmentSession(ctx context.Context, userID int, username, ip string) (string, error) {
	return m.CreateTwoFASession(ctx, userID, username, ip, true)
}

// ValidateTwoFASession validates and retrieves a 2FA session with IP validation
func (m *TwoFASessionManager) ValidateTwoFASession(ctx context.Context, token, ip string) (*TwoFASessionData, error) {
	key := fmt.Sprintf("twofa:session:%s", token)

	// Retrieve session data
	data, err := m.redis.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("2FA session not found or expired")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve 2FA session: %w", err)
	}

	// Deserialize
	var sessionData TwoFASessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal 2FA session data: %w", err)
	}

	// Validate IP address
	if !m.validateIP(sessionData.IP, ip) {
		m.logger.Warn("2FA session IP mismatch",
			"user_id", sessionData.UserID,
			"session_ip", sessionData.IP,
			"request_ip", ip,
		)
		return nil, fmt.Errorf("IP address mismatch")
	}

	return &sessionData, nil
}

// validateIP validates request IP against session IP with proxy support
func (m *TwoFASessionManager) validateIP(sessionIP, requestIP string) bool {
	// Check if request IP is from trusted proxy
	// If using X-Forwarded-For, this logic can be extended
	// For now, require exact match
	return sessionIP == requestIP
}

// ExtractClientIP extracts client IP from request, considering X-Forwarded-For
func (m *TwoFASessionManager) ExtractClientIP(remoteAddr, xForwardedFor string) string {
	// If X-Forwarded-For header exists and we have trusted proxies
	if xForwardedFor != "" && len(m.config.TwoFactor.TrustedProxyIPs) > 0 {
		// Get first IP from X-Forwarded-For (client IP)
		parts := strings.Split(xForwardedFor, ",")
		if len(parts) > 0 {
			clientIP := strings.TrimSpace(parts[0])
			// Verify the request came from trusted proxy
			if m.isTrustedProxy(remoteAddr) {
				return clientIP
			}
		}
	}

	// Fallback to direct connection IP
	// Remove port if present
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		return remoteAddr[:idx]
	}
	return remoteAddr
}

// isTrustedProxy checks if an IP is in the trusted proxy list
func (m *TwoFASessionManager) isTrustedProxy(ip string) bool {
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	for _, trustedIP := range m.config.TwoFactor.TrustedProxyIPs {
		if ip == trustedIP {
			return true
		}
	}
	return false
}

// DestroyTwoFASession deletes a 2FA session
func (m *TwoFASessionManager) DestroyTwoFASession(ctx context.Context, token string) error {
	key := fmt.Sprintf("twofa:session:%s", token)
	if err := m.redis.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to destroy 2FA session: %w", err)
	}

	m.logger.Info("Destroyed 2FA session", "token", token[:8]+"...")
	return nil
}

// TrackTwoFAAttempts increments failed attempt counter for a session
func (m *TwoFASessionManager) TrackTwoFAAttempts(ctx context.Context, token string) (int, error) {
	key := fmt.Sprintf("twofa:attempts:%s", token)

	// Increment counter
	attempts, err := m.redis.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to increment attempt counter: %w", err)
	}

	// Set expiration matching session timeout (if first attempt)
	if attempts == 1 {
		ttl := time.Duration(m.config.TwoFactor.SessionTimeout) * time.Second
		if err := m.redis.Expire(ctx, key, ttl).Err(); err != nil {
			return int(attempts), fmt.Errorf("failed to set attempt counter expiration: %w", err)
		}
	}

	m.logger.Info("Tracked 2FA attempt", "token", token[:8]+"...", "attempts", attempts)
	return int(attempts), nil
}

// LockAccount locks a user account for 1 hour timeout
func (m *TwoFASessionManager) LockAccount(ctx context.Context, userID int) error {
	key := fmt.Sprintf("twofa:locked:%d", userID)
	ttl := time.Duration(m.config.TwoFactor.LockoutDuration) * time.Second

	// Set lockout flag with TTL
	if err := m.redis.Set(ctx, key, "1", ttl).Err(); err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	m.logger.Warn("Locked user account",
		"user_id", userID,
		"duration_seconds", m.config.TwoFactor.LockoutDuration,
	)

	return nil
}

// IsAccountLocked checks if a user account is currently locked
func (m *TwoFASessionManager) IsAccountLocked(ctx context.Context, userID int) (bool, error) {
	key := fmt.Sprintf("twofa:locked:%d", userID)

	exists, err := m.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check account lock status: %w", err)
	}

	return exists > 0, nil
}

// GetLockoutExpiry returns the remaining lockout duration (0 if not locked)
func (m *TwoFASessionManager) GetLockoutExpiry(ctx context.Context, userID int) (time.Duration, error) {
	key := fmt.Sprintf("twofa:locked:%d", userID)

	ttl, err := m.redis.TTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get lockout expiry: %w", err)
	}

	// If key doesn't exist or no TTL, return 0
	if ttl < 0 {
		return 0, nil
	}

	return ttl, nil
}
