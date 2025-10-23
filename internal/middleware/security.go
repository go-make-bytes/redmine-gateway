package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/go-make-bytes/redmine-gateway/internal/logger"
)

// SecurityMiddleware provides various security enhancements
type SecurityMiddleware struct {
	redis  *redis.Client
	logger *logger.Logger
}

// NewSecurityMiddleware creates a new security middleware instance
func NewSecurityMiddleware(redis *redis.Client, logger *logger.Logger) *SecurityMiddleware {
	return &SecurityMiddleware{
		redis:  redis,
		logger: logger,
	}
}

// SecurityHeaders adds security headers to all responses
func (s *SecurityMiddleware) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Allow data: URIs for images (wwas added for needed for QR codes in 2FA enrollment before TwoFASecurityHeaders func)
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// TwoFASecurityHeaders adds enhanced security headers specifically for 2FA endpoints
func (s *SecurityMiddleware) TwoFASecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Standard security headers
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Enhanced CSP for 2FA pages (allow QR code images and minimal inline scripts)
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; frame-ancestors 'none'")

		// Prevent caching of 2FA pages
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		// Custom header to indicate 2FA protection
		c.Header("X-2FA-Protected", "true")

		// Additional headers for authentication flows
		c.Header("X-Content-Security-Policy", "default-src 'self'") // IE support
		c.Header("X-WebKit-CSP", "default-src 'self'")              // WebKit support

		c.Next()
	}
}

// RateLimiter implements rate limiting for login attempts
func (s *SecurityMiddleware) RateLimiter(maxAttempts int, windowMinutes int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.Background()
		clientIP := c.ClientIP()
		key := fmt.Sprintf("rate_limit:login:%s", clientIP)

		// Get current attempt count
		attempts, err := s.redis.Get(ctx, key).Int()
		if err != nil && err != redis.Nil {
			s.logger.Logger.WithField("error", err.Error()).Error("Failed to get rate limit count")
			c.Next()
			return
		}

		if attempts >= maxAttempts {
			s.logger.SecurityLog("rate_limit_exceeded", 0, clientIP, map[string]interface{}{
				"attempts":       attempts,
				"max_attempts":   maxAttempts,
				"window_minutes": windowMinutes,
			})

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "too_many_attempts",
				"error_description": fmt.Sprintf("Too many login attempts. Try again in %d minutes.", windowMinutes),
				"retry_after":       windowMinutes * 60,
			})
			c.Abort()
			return
		}

		c.Next()

		// If this was a login attempt, increment counter
		if c.Request.URL.Path == "/auth/login" && c.Request.Method == "POST" {
			// Only increment on failed attempts (status >= 400)
			if c.Writer.Status() >= 400 {
				pipe := s.redis.Pipeline()
				pipe.Incr(ctx, key)
				pipe.Expire(ctx, key, time.Duration(windowMinutes)*time.Minute)
				_, err := pipe.Exec(ctx)
				if err != nil {
					s.logger.Logger.WithField("error", err.Error()).Error("Failed to update rate limit")
				}
			} else {
				// Clear rate limit on successful login
				s.redis.Del(ctx, key)
			}
		}
	}
}

// TwoFARateLimiter implements rate limiting specifically for 2FA verification attempts
func (s *SecurityMiddleware) TwoFARateLimiter(maxAttempts int, windowMinutes int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.Background()
		clientIP := c.ClientIP()
		key := fmt.Sprintf("rate_limit:twofa:%s", clientIP)

		// Get current attempt count
		attempts, err := s.redis.Get(ctx, key).Int()
		if err != nil && err != redis.Nil {
			s.logger.Logger.WithField("error", err.Error()).Error("Failed to get 2FA rate limit count")
			c.Next()
			return
		}

		if attempts >= maxAttempts {
			s.logger.SecurityLog("twofa_rate_limit_exceeded", 0, clientIP, map[string]interface{}{
				"attempts":       attempts,
				"max_attempts":   maxAttempts,
				"window_minutes": windowMinutes,
				"path":           c.Request.URL.Path,
			})

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "too_many_twofa_attempts",
				"error_description": fmt.Sprintf("Too many 2FA verification attempts. Try again in %d minutes.", windowMinutes),
				"retry_after":       windowMinutes * 60,
			})
			c.Abort()
			return
		}

		c.Next()

		// If this was a 2FA verification attempt, increment counter
		if strings.HasPrefix(c.Request.URL.Path, "/auth/2fa/") && c.Request.Method == "POST" {
			// Only increment on failed attempts (status >= 400)
			if c.Writer.Status() >= 400 {
				pipe := s.redis.Pipeline()
				pipe.Incr(ctx, key)
				pipe.Expire(ctx, key, time.Duration(windowMinutes)*time.Minute)
				_, err := pipe.Exec(ctx)
				if err != nil {
					s.logger.Logger.WithField("error", err.Error()).Error("Failed to update 2FA rate limit")
				}
			} else {
				// Clear rate limit on successful 2FA verification
				s.redis.Del(ctx, key)
			}
		}
	}
}

// CSRFProtection provides CSRF token validation
type CSRFProtection struct {
	redis  *redis.Client
	logger *logger.Logger
	secret string
}

// NewCSRFProtection creates a new CSRF protection middleware
func NewCSRFProtection(redis *redis.Client, logger *logger.Logger, secret string) *CSRFProtection {
	return &CSRFProtection{
		redis:  redis,
		logger: logger,
		secret: secret,
	}
}

// GenerateToken generates a new CSRF token for a session
func (c *CSRFProtection) GenerateToken(sessionID string) (string, error) {
	ctx := context.Background()
	token := generateSecureToken(32)
	key := fmt.Sprintf("csrf:%s", token)

	err := c.redis.Set(ctx, key, sessionID, 30*time.Minute).Err()
	if err != nil {
		return "", fmt.Errorf("failed to store CSRF token: %w", err)
	}

	return token, nil
}

// ValidateToken validates a CSRF token against a session
func (c *CSRFProtection) ValidateToken(token, sessionID string) bool {
	ctx := context.Background()
	key := fmt.Sprintf("csrf:%s", token)

	storedSession, err := c.redis.Get(ctx, key).Result()
	if err != nil || storedSession != sessionID {
		return false
	}

	// Single use token - delete after validation
	c.redis.Del(ctx, key)
	return true
}

// Middleware returns the CSRF validation middleware
func (c *CSRFProtection) Middleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Skip CSRF for GET requests and specific endpoints
		if ctx.Request.Method == "GET" ||
			strings.HasPrefix(ctx.Request.URL.Path, "/oauth/token") ||
			strings.HasPrefix(ctx.Request.URL.Path, "/api/") {
			ctx.Next()
			return
		}

		// Get CSRF token from header or form
		token := ctx.GetHeader("X-CSRF-Token")
		if token == "" {
			token = ctx.PostForm("csrf_token")
		}

		if token == "" {
			c.logger.SecurityLog("csrf_token_missing", 0, ctx.ClientIP(), map[string]interface{}{
				"path":   ctx.Request.URL.Path,
				"method": ctx.Request.Method,
			})

			ctx.JSON(http.StatusForbidden, gin.H{
				"error":             "csrf_token_required",
				"error_description": "CSRF token is required",
			})
			ctx.Abort()
			return
		}

		// Get session from cookie
		sessionCookie, err := ctx.Cookie("auth_session")
		if err != nil {
			ctx.JSON(http.StatusForbidden, gin.H{
				"error":             "session_required",
				"error_description": "Valid session is required",
			})
			ctx.Abort()
			return
		}

		if !c.ValidateToken(token, sessionCookie) {
			c.logger.SecurityLog("csrf_validation_failed", 0, ctx.ClientIP(), map[string]interface{}{
				"token":   token,
				"session": sessionCookie,
				"path":    ctx.Request.URL.Path,
			})

			ctx.JSON(http.StatusForbidden, gin.H{
				"error":             "invalid_csrf_token",
				"error_description": "Invalid CSRF token",
			})
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// InputValidator provides input validation and sanitization
type InputValidator struct {
	maxUsernameLength int
	maxPasswordLength int
}

// NewInputValidator creates a new input validator
func NewInputValidator(maxUsernameLength, maxPasswordLength int) *InputValidator {
	return &InputValidator{
		maxUsernameLength: maxUsernameLength,
		maxPasswordLength: maxPasswordLength,
	}
}

// ValidateCredentials validates username and password inputs
func (v *InputValidator) ValidateCredentials(username, password string) error {
	// Username validation
	if len(username) == 0 {
		return fmt.Errorf("username is required")
	}
	if len(username) > v.maxUsernameLength {
		return fmt.Errorf("username too long (max %d characters)", v.maxUsernameLength)
	}

	// Check for malicious patterns in username
	dangerous := []string{
		"<script", "</script>", "javascript:", "vbscript:",
		"onload=", "onerror=", "onclick=", "onmouseover=",
		"'", "\"", "--", "/*", "*/", "xp_", "sp_",
		"DROP", "DELETE", "INSERT", "UPDATE", "SELECT",
		"UNION", "OR 1=1", "AND 1=1", "; --",
	}

	usernameLower := strings.ToLower(username)
	for _, pattern := range dangerous {
		if strings.Contains(usernameLower, strings.ToLower(pattern)) {
			return fmt.Errorf("username contains invalid characters")
		}
	}

	// Password validation
	if len(password) == 0 {
		return fmt.Errorf("password is required")
	}
	if len(password) > v.maxPasswordLength {
		return fmt.Errorf("password too long (max %d characters)", v.maxPasswordLength)
	}

	return nil
}

// SanitizeInput sanitizes string input
func (v *InputValidator) SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	return input
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to generate secure token: %v", err))
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}
