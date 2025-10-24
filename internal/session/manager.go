package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/go-make-bytes/redmine-gateway/internal/logger"
)

// SessionManager handles secure session management
type SessionManager struct {
	redis  *redis.Client
	logger *logger.Logger
	ttl    time.Duration
}

// SessionData represents session information
type SessionData struct {
	UserID       int       `json:"user_id"`
	Username     string    `json:"username"`
	ClientIP     string    `json:"client_ip"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	LastAccessed time.Time `json:"last_accessed"`
	CSRFToken    string    `json:"csrf_token"`
	ReturnTo     string    `json:"return_to,omitempty"`
}

// MarshalBinary implements encoding.BinaryMarshaler for Redis serialization
func (s *SessionData) MarshalBinary() ([]byte, error) {
	return json.Marshal(s)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for Redis deserialization
func (s *SessionData) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, s)
}

// NewSessionManager creates a new session manager
func NewSessionManager(redis *redis.Client, logger *logger.Logger, ttl time.Duration) *SessionManager {
	return &SessionManager{
		redis:  redis,
		logger: logger,
		ttl:    ttl,
	}
}

// CreateSession creates a new secure session
func (sm *SessionManager) CreateSession(userID int, username, clientIP, userAgent string) (string, string, error) {
	return sm.CreateSessionWithReturnTo(userID, username, clientIP, userAgent, "")
}

// CreateSessionWithReturnTo creates a new secure session with optional return URL
func (sm *SessionManager) CreateSessionWithReturnTo(userID int, username, clientIP, userAgent, returnTo string) (string, string, error) {
	ctx := context.Background()

	// Generate secure session token
	sessionToken := generateSecureToken(40)
	csrfToken := generateSecureToken(32)

	sessionData := &SessionData{
		UserID:       userID,
		Username:     username,
		ClientIP:     clientIP,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
		LastAccessed: time.Now(),
		CSRFToken:    csrfToken,
		ReturnTo:     returnTo,
	}

	sessionKey := fmt.Sprintf("auth_session:%s", sessionToken)
	err := sm.redis.Set(ctx, sessionKey, sessionData, sm.ttl).Err()
	if err != nil {
		sm.logger.Logger.WithField("error", err.Error()).Error("Failed to create session")
		return "", "", fmt.Errorf("failed to create session: %w", err)
	}

	sm.logger.SecurityLog("session_created", userID, clientIP, map[string]interface{}{
		"session_id": sessionToken,
		"username":   username,
		"expires_at": time.Now().Add(sm.ttl),
	})

	return sessionToken, csrfToken, nil
}

// ValidateSession validates and refreshes a session
func (sm *SessionManager) ValidateSession(sessionToken, clientIP, userAgent string) (*SessionData, error) {
	ctx := context.Background()
	sessionKey := fmt.Sprintf("auth_session:%s", sessionToken)

	var sessionData SessionData
	err := sm.redis.Get(ctx, sessionKey).Scan(&sessionData)
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found or expired")
		}
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	// Validate session IP and User Agent for security
	if sessionData.ClientIP != clientIP {
		sm.logger.SecurityLog("session_ip_mismatch", sessionData.UserID, clientIP, map[string]interface{}{
			"session_ip": sessionData.ClientIP,
			"request_ip": clientIP,
			"session_id": sessionToken,
		})
		return nil, fmt.Errorf("session IP mismatch")
	}

	if sessionData.UserAgent != userAgent {
		sm.logger.SecurityLog("session_ua_mismatch", sessionData.UserID, clientIP, map[string]interface{}{
			"session_ua": sessionData.UserAgent,
			"request_ua": userAgent,
			"session_id": sessionToken,
		})
		return nil, fmt.Errorf("session user agent mismatch")
	}

	// Update last accessed time and refresh TTL
	sessionData.LastAccessed = time.Now()
	err = sm.redis.Set(ctx, sessionKey, &sessionData, sm.ttl).Err()
	if err != nil {
		sm.logger.Logger.WithField("error", err.Error()).Error("Failed to refresh session")
		// Don't fail validation just because we couldn't refresh
	}

	return &sessionData, nil
}

// DestroySession removes a session
func (sm *SessionManager) DestroySession(sessionToken string) error {
	ctx := context.Background()
	sessionKey := fmt.Sprintf("auth_session:%s", sessionToken)

	// Get session data for logging before deletion
	var sessionData SessionData
	err := sm.redis.Get(ctx, sessionKey).Scan(&sessionData)
	if err == nil {
		sm.logger.SecurityLog("session_destroyed", sessionData.UserID, sessionData.ClientIP, map[string]interface{}{
			"session_id": sessionToken,
			"username":   sessionData.Username,
		})
	}

	err = sm.redis.Del(ctx, sessionKey).Err()
	if err != nil {
		return fmt.Errorf("failed to destroy session: %w", err)
	}

	return nil
}

// GetSession retrieves session data without validation
func (sm *SessionManager) GetSession(sessionToken string) (*SessionData, error) {
	ctx := context.Background()
	sessionKey := fmt.Sprintf("auth_session:%s", sessionToken)

	var sessionData SessionData
	err := sm.redis.Get(ctx, sessionKey).Scan(&sessionData)
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	return &sessionData, nil
}

// CleanupExpiredSessions removes expired sessions (called by background job)
func (sm *SessionManager) CleanupExpiredSessions() error {
	ctx := context.Background()

	// Redis automatically handles TTL expiration, but we can log cleanup stats
	pattern := "auth_session:*"
	keys, err := sm.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get session keys: %w", err)
	}

	activeSessionCount := len(keys)
	sm.logger.Logger.WithField("active_sessions", activeSessionCount).Info("Session cleanup completed")

	return nil
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
