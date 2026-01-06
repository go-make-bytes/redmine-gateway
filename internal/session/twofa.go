package session

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	// twofaSessionKeyFormat is the Redis key format for 2FA sessions
	twofaSessionKeyFormat = "%stwofa:session:%s"
	// twofaAttemptsKeyFormat is the Redis key format for 2FA attempt counters
	twofaAttemptsKeyFormat = "%stwofa:attempts:%s"
	// twofaLockedKeyFormat is the Redis key format for locked accounts
	twofaLockedKeyFormat = "%stwofa:locked:%d"
)

// TwoFASessionManager handles 2FA session management
type TwoFASessionManager struct {
	redis  *redis.Client
	logger *logger.Logger
	config *config.Config
	prefix string
}

// TwoFASessionData represents temporary 2FA session data
type TwoFASessionData struct {
	UserID         int       `json:"user_id"`
	Username       string    `json:"username"`
	IP             string    `json:"ip"`
	Attempts       int       `json:"attempts"`
	CreatedAt      time.Time `json:"created_at"`
	EnrollmentMode bool      `json:"enrollment_mode,omitempty"`
	AuthMethod     string    `json:"auth_method,omitempty"`    // "ldap" or "database"
	AuthSourceID   *int      `json:"auth_source_id,omitempty"` // LDAP source ID if auth_method="ldap"
}

// NewTwoFASessionManager creates a new 2FA session manager
func NewTwoFASessionManager(redis *redis.Client, logger *logger.Logger, cfg *config.Config, prefix string) *TwoFASessionManager {
	return &TwoFASessionManager{
		redis:  redis,
		logger: logger,
		config: cfg,
		prefix: prefix,
	}
}

// CreateTwoFASession creates a new temporary 2FA session with 5 minutes timeout
func (m *TwoFASessionManager) CreateTwoFASession(ctx context.Context, userID int, username, ip string, enrollmentMode bool, authMethod string, authSourceID *int) (string, error) {
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
		AuthMethod:     authMethod,
		AuthSourceID:   authSourceID,
	}

	// Store in Redis as hash
	key := fmt.Sprintf(twofaSessionKeyFormat, m.prefix, token)
	fields := map[string]interface{}{
		"user_id":         sessionData.UserID,
		"username":        sessionData.Username,
		"ip":              sessionData.IP,
		"attempts":        sessionData.Attempts,
		"created_at":      sessionData.CreatedAt.Format(time.RFC3339),
		"enrollment_mode": fmt.Sprintf("%t", sessionData.EnrollmentMode),
		"auth_method":     sessionData.AuthMethod,
	}

	// Add auth_source_id if present
	if sessionData.AuthSourceID != nil {
		fields["auth_source_id"] = *sessionData.AuthSourceID
	}

	if err := m.redis.HSet(ctx, key, fields).Err(); err != nil {
		return "", fmt.Errorf("failed to create 2FA session: %w", err)
	}

	// Set expiration
	ttl := time.Duration(m.config.TwoFactor.SessionTimeout) * time.Second
	if err := m.redis.Expire(ctx, key, ttl).Err(); err != nil {
		return "", fmt.Errorf("failed to set 2FA session expiration: %w", err)
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
		"auth_method", authMethod,
		"ip", ip,
		"ttl_seconds", m.config.TwoFactor.SessionTimeout,
		"timestamp", time.Now().Unix(),
	)

	return token, nil
}

// CreateEnrollmentSession creates a new 2FA enrollment session
// This is a convenience wrapper for CreateTwoFASession with enrollment mode enabled
func (m *TwoFASessionManager) CreateEnrollmentSession(ctx context.Context, userID int, username, ip string) (string, error) {
	return m.CreateTwoFASession(ctx, userID, username, ip, true, "database", nil)
}

// ValidateTwoFASession validates and retrieves a 2FA session with enhanced IP validation
func (m *TwoFASessionManager) ValidateTwoFASession(ctx context.Context, token, ip string) (*TwoFASessionData, error) {
	key := fmt.Sprintf(twofaSessionKeyFormat, m.prefix, token)

	// Retrieve session data from hash
	data, err := m.redis.HGetAll(ctx, key).Result()
	if err != nil {
		m.logger.Error("Failed to retrieve 2FA session from Redis",
			"error", err.Error(),
			"token_prefix", token[:8]+"...",
		)
		return nil, fmt.Errorf("failed to retrieve 2FA session: %w", err)
	}

	if len(data) == 0 {
		m.logger.Warn("2FA session validation failed: session not found or expired",
			"token_prefix", token[:8]+"...",
			"request_ip", ip,
		)
		return nil, fmt.Errorf("2FA session not found or expired")
	}

	// Parse session data
	userID, _ := strconv.Atoi(data["user_id"])
	attempts, _ := strconv.Atoi(data["attempts"])
	enrollmentMode, _ := strconv.ParseBool(data["enrollment_mode"])
	createdAt, _ := time.Parse(time.RFC3339, data["created_at"])

	// Parse optional auth fields
	authMethod := data["auth_method"]
	var authSourceID *int
	if authSourceIDStr, exists := data["auth_source_id"]; exists && authSourceIDStr != "" {
		if id, err := strconv.Atoi(authSourceIDStr); err == nil {
			authSourceID = &id
		}
	}

	sessionData := &TwoFASessionData{
		UserID:         userID,
		Username:       data["username"],
		IP:             data["ip"],
		Attempts:       attempts,
		CreatedAt:      createdAt,
		EnrollmentMode: enrollmentMode,
		AuthMethod:     authMethod,
		AuthSourceID:   authSourceID,
	}

	// Enhanced IP validation
	if !m.validateIP(sessionData.IP, ip) {
		m.logger.Warn("2FA session validation failed: IP mismatch",
			"user_id", sessionData.UserID,
			"username", sessionData.Username,
			"session_ip", sessionData.IP,
			"request_ip", ip,
			"enrollment_mode", sessionData.EnrollmentMode,
			"session_age_seconds", time.Since(sessionData.CreatedAt).Seconds(),
		)
		return nil, fmt.Errorf("IP address validation failed")
	}

	// Log successful validation
	m.logger.Info("2FA session validated successfully",
		"user_id", sessionData.UserID,
		"username", sessionData.Username,
		"enrollment_mode", sessionData.EnrollmentMode,
		"session_age_seconds", time.Since(sessionData.CreatedAt).Seconds(),
	)

	return sessionData, nil
}

// validateIP validates request IP against session IP with enhanced security checks
func (m *TwoFASessionManager) validateIP(sessionIP, requestIP string) bool {
	// Basic validation: exact match
	if sessionIP == requestIP {
		return true
	}

	// Check if request IP is from trusted proxy with CIDR validation
	if m.isTrustedProxyCIDR(requestIP) {
		// Additional validation: ensure session IP is not a private/internal IP
		// when coming through a trusted proxy (prevents IP spoofing)
		if m.isPrivateIP(sessionIP) {
			m.logger.Warn("Potential IP spoofing attempt: private IP through trusted proxy",
				"session_ip", sessionIP,
				"request_ip", requestIP,
			)
			return false
		}
		return true
	}

	// Log IP mismatch for security monitoring
	m.logger.Warn("2FA session IP validation failed",
		"session_ip", sessionIP,
		"request_ip", requestIP,
		"trusted_proxies", m.config.TwoFactor.TrustedProxyIPs,
	)

	return false
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

// isTrustedProxyCIDR checks if an IP is in the trusted proxy CIDR ranges
func (m *TwoFASessionManager) isTrustedProxyCIDR(ip string) bool {
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// For now, use exact match with configured trusted proxies
	// In production, this should be enhanced to support CIDR ranges
	for _, trustedIP := range m.config.TwoFactor.TrustedProxyIPs {
		if ip == trustedIP {
			return true
		}
	}
	return false
}

// isPrivateIP checks if an IP address is in a private range
func (m *TwoFASessionManager) isPrivateIP(ip string) bool {
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Check for private IPv4 ranges
	privateRanges := []string{
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
	}

	// Simple string-based check (in production, use proper CIDR parsing)
	for _, ipRange := range privateRanges {
		if strings.HasPrefix(ipRange, ip[:strings.LastIndex(ipRange, "/")]) {
			return true
		}
	}

	return false
}

// DestroyTwoFASession deletes a 2FA session
func (m *TwoFASessionManager) DestroyTwoFASession(ctx context.Context, token string) error {
	key := fmt.Sprintf(twofaSessionKeyFormat, m.prefix, token)
	if err := m.redis.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to destroy 2FA session: %w", err)
	}

	m.logger.Info("Destroyed 2FA session", "token", token[:8]+"...")
	return nil
}

// TrackTwoFAAttempts increments failed attempt counter for a session
func (m *TwoFASessionManager) TrackTwoFAAttempts(ctx context.Context, token string) (int, error) {
	key := fmt.Sprintf(twofaAttemptsKeyFormat, m.prefix, token)

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

	// Check if we need to lock the account
	if attempts >= int64(m.config.TwoFactor.MaxAttempts) {
		// Get session data to find user ID
		sessionKey := fmt.Sprintf(twofaSessionKeyFormat, m.prefix, token)
		userIDStr, err := m.redis.HGet(ctx, sessionKey, "user_id").Result()
		if err == nil {
			if userID, parseErr := strconv.Atoi(userIDStr); parseErr == nil {
				// Lock the account
				if lockErr := m.LockAccount(ctx, userID); lockErr != nil {
					m.logger.Error("Failed to lock account after max attempts",
						"error", lockErr.Error(),
						"user_id", userID,
						"attempts", attempts,
					)
				}
			}
		}
	}

	m.logger.Info("Tracked 2FA attempt", "token", token[:8]+"...", "attempts", attempts)
	return int(attempts), nil
}

// LockAccount locks a user account for 1 hour timeout
func (m *TwoFASessionManager) LockAccount(ctx context.Context, userID int) error {
	key := fmt.Sprintf(twofaLockedKeyFormat, m.prefix, userID)
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
	key := fmt.Sprintf(twofaLockedKeyFormat, m.prefix, userID)

	exists, err := m.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check account lock status: %w", err)
	}

	return exists > 0, nil
}

// GetLockoutExpiry returns the remaining lockout duration (0 if not locked)
func (m *TwoFASessionManager) GetLockoutExpiry(ctx context.Context, userID int) (time.Duration, error) {
	key := fmt.Sprintf(twofaLockedKeyFormat, m.prefix, userID)

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
