package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/middleware"
	"github.com/go-make-bytes/redmine-gateway/internal/router/requests"
	"github.com/go-make-bytes/redmine-gateway/internal/router/responses"
	"github.com/go-make-bytes/redmine-gateway/internal/session"
)

// AuthHandler handles secure authentication endpoints
type AuthHandler struct {
	cfg             *config.Config
	db              *database.PostgreSQL
	logger          *logger.Logger
	sessionManager  *session.SessionManager
	twoFASessionMgr *session.TwoFASessionManager
	validator       *middleware.InputValidator
	csrfProtection  *middleware.CSRFProtection
	redis           *redis.Client
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(
	cfg *config.Config,
	db *database.PostgreSQL,
	logger *logger.Logger,
	sessionManager *session.SessionManager,
	twoFASessionMgr *session.TwoFASessionManager,
	validator *middleware.InputValidator,
	csrfProtection *middleware.CSRFProtection,
	redis *redis.Client,
) *AuthHandler {
	return &AuthHandler{
		cfg:             cfg,
		db:              db,
		logger:          logger,
		sessionManager:  sessionManager,
		twoFASessionMgr: twoFASessionMgr,
		validator:       validator,
		csrfProtection:  csrfProtection,
		redis:           redis,
	}
}

// checkAndEnforceTwoFactor checks if 2FA is required and returns appropriate response
func (h *AuthHandler) checkAndEnforceTwoFactor(c *gin.Context, user *database.User) bool {
	ctx := context.Background()

	// Check if 2FA is enabled at the gateway level
	if !h.cfg.TwoFactor.Enabled {
		return false // Continue with normal flow
	}

	// Get user's 2FA data to check if they have it configured
	twoFAData, err := h.db.GetUserTwoFactorData(ctx, user.ID)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to get 2FA data")
		c.JSON(http.StatusInternalServerError, responses.NewErrorResponse(
			"server_error",
			"Failed to verify 2FA status",
		))
		return true // Stop processing
	}

	// When TWOFA_ENABLED=true, all users must have 2FA
	// Determine if user needs to enroll or verify
	hasTotp := twoFAData.Scheme.Valid && twoFAData.Scheme.String == "totp"
	enrollmentMode := !hasTotp

	// Extract client IP
	clientIP := h.twoFASessionMgr.ExtractClientIP(c.ClientIP(), c.GetHeader("X-Forwarded-For"))

	// Create temporary 2FA session
	twoFAToken, err := h.twoFASessionMgr.CreateTwoFASession(ctx, user.ID, user.Login, clientIP, enrollmentMode)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to create 2FA session")
		c.JSON(http.StatusInternalServerError, responses.NewErrorResponse(
			"server_error",
			"Failed to initiate 2FA verification",
		))
		return true // Stop processing
	}

	h.logger.SecurityLog("2fa_challenge_issued", user.ID, clientIP, map[string]interface{}{
		"username":        user.Login,
		"enrollment_mode": enrollmentMode,
	})

	// Return 2FA challenge response
	c.JSON(http.StatusOK, responses.TwoFAChallengeResponse{
		RequiresTwoFA:  true,
		SessionToken:   twoFAToken,
		EnrollmentMode: enrollmentMode,
		Message:        "Two-factor authentication required",
		TimeoutSeconds: h.cfg.TwoFactor.SessionTimeout,
		MaxAttempts:    h.cfg.TwoFactor.MaxAttempts,
	})
	return true // Stop processing
}

// Login handles secure authentication
func (h *AuthHandler) Login(c *gin.Context) {
	ctx := context.Background()

	var req requests.AuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.SecurityLog("invalid_auth_request", 0, c.ClientIP(), map[string]interface{}{
			"error": err.Error(),
		})

		c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
			"invalid_request",
			"Invalid request format",
		))
		return
	}

	// Sanitize inputs
	req.Username = h.validator.SanitizeInput(req.Username)
	req.Password = h.validator.SanitizeInput(req.Password)

	// Validate credentials format
	if err := h.validator.ValidateCredentials(req.Username, req.Password); err != nil {
		h.logger.SecurityLog("invalid_credentials_format", 0, c.ClientIP(), map[string]interface{}{
			"username": req.Username,
			"error":    err.Error(),
		})

		c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
			"invalid_request",
			err.Error(),
		))
		return
	}

	h.logger.SecurityLog("login_attempt", 0, c.ClientIP(), map[string]interface{}{
		"username": req.Username,
	})

	// Authenticate against PostgreSQL database
	user, err := h.db.AuthenticateUser(ctx, req.Username, req.Password)
	if err != nil {
		h.logger.SecurityLog("authentication_failed", 0, c.ClientIP(), map[string]interface{}{
			"username": req.Username,
			"error":    err.Error(),
		})

		c.JSON(http.StatusUnauthorized, responses.NewErrorResponse(
			"invalid_credentials",
			"Invalid username or password",
		))
		return
	}

	// Check if password change is required (takes precedence over 2FA)
	if user.MustChangePassword {
		// Try to get return_to from temp session
		returnTo := ""
		tempSessionToken, err := c.Cookie("temp_session")
		if err == nil && tempSessionToken != "" {
			ctx := context.Background()
			returnTo, _ = h.redis.Get(ctx, "temp_return_to:"+tempSessionToken).Result()
			// Clean up temp data
			h.redis.Del(ctx, "temp_return_to:"+tempSessionToken)
		}

		h.logger.SecurityLog("password_change_required", user.ID, c.ClientIP(), map[string]interface{}{
			"username": user.Login,
		})

		c.JSON(http.StatusOK, responses.PasswordChangeRequiredResponse{
			RequiresPasswordChange: true,
			UserID:                 user.ID,
			ReturnTo:               returnTo,
			Message:                "Password change is required before proceeding",
		})
		return
	}

	// Check if 2FA is enabled at the gateway level
	if h.checkAndEnforceTwoFactor(c, user) {
		return
	}

	// Create secure session
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	sessionToken, csrfToken, err := h.sessionManager.CreateSession(user.ID, user.Login, clientIP, userAgent)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to create session")
		c.JSON(http.StatusInternalServerError, responses.NewErrorResponse(
			"server_error",
			"Failed to create session",
		))
		return
	}

	h.logger.SecurityLog("authentication_success", user.ID, clientIP, map[string]interface{}{
		"username":   user.Login,
		"session_id": sessionToken,
	})

	// Set secure cookie
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(
		"auth_session", // name
		sessionToken,   // value
		900,            // maxAge (15 minutes)
		"/",            // path
		"",             // domain
		true,           // secure (HTTPS only)
		true,           // httpOnly
	)

	c.JSON(http.StatusOK, responses.AuthResponse{
		Authenticated: true,
		SessionToken:  sessionToken,
		UserID:        user.ID,
		ExpiresIn:     900,
		CSRFToken:     csrfToken,
	})
}

// Logout destroys the current session
func (h *AuthHandler) Logout(c *gin.Context) {
	sessionToken, err := c.Cookie("auth_session")
	if err != nil {
		c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
			"no_session",
			"No active session found",
		))
		return
	}

	// Destroy session
	err = h.sessionManager.DestroySession(sessionToken)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to destroy session")
		// Continue anyway to clear cookie
	}

	// Clear cookie
	c.SetCookie("auth_session", "", -1, "/", "", true, true)

	c.JSON(http.StatusOK, responses.LogoutResponse{
		Message: "Logged out successfully",
	})
}

// CheckSession validates current session
func (h *AuthHandler) CheckSession(c *gin.Context) {
	sessionToken, err := c.Cookie("auth_session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, responses.SessionCheckResponse{
			Authenticated: false,
			Error:         "no_session",
		})
		return
	}

	sessionData, err := h.sessionManager.ValidateSession(sessionToken, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, responses.SessionCheckResponse{
			Authenticated: false,
			Error:         "invalid_session",
		})
		return
	}

	c.JSON(http.StatusOK, responses.SessionCheckResponse{
		Authenticated: true,
		UserID:        sessionData.UserID,
		Username:      sessionData.Username,
		ExpiresIn:     int(time.Until(sessionData.LastAccessed.Add(15 * time.Minute)).Seconds()),
	})
}

// ShowLoginPage displays the secure login page
func (h *AuthHandler) ShowLoginPage(c *gin.Context) {
	returnTo := c.Query("return_to")

	// Store return_to in a temporary session for the login flow
	if returnTo != "" {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		// Create a temporary session just to store the return_to
		tempToken, _, err := h.sessionManager.CreateSession(0, "temp", clientIP, userAgent)
		if err == nil {
			// Store return_to in Redis with the temp token
			ctx := context.Background()
			h.redis.Set(ctx, "temp_return_to:"+tempToken, returnTo, 10*time.Minute)
			c.SetCookie("temp_session", tempToken, 600, "/", "", true, true)
		}
	}

	c.HTML(http.StatusOK, "secure_login.html", gin.H{
		"return_to": returnTo,
		"title":     "Secure Login",
	})
}

// ShowPasswordChangePage displays the password change page
func (h *AuthHandler) ShowPasswordChangePage(c *gin.Context) {
	userIDStr := c.Query("user_id")
	returnTo := c.Query("return_to")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
			"invalid_request",
			"User ID is required",
		))
		return
	}

	// Validate user exists and needs password change
	ctx := context.Background()
	userID := 0
	if parsedID, err := strconv.Atoi(userIDStr); err == nil {
		userID = parsedID
	}

	user, err := h.db.GetUserByID(ctx, userID)
	if err != nil {
		h.logger.SecurityLog("password_change_page_access_denied", userID, c.ClientIP(), map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusNotFound, responses.NewErrorResponse(
			"user_not_found",
			"User not found",
		))
		return
	}

	if !user.MustChangePassword {
		// Check if client accepts HTML (browser request) vs JSON (API request)
		accept := c.GetHeader("Accept")
		if strings.Contains(accept, "text/html") {
			// Browser request - show error page
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"title":             "Password Change Not Required",
				"error":             "password_change_not_required",
				"error_description": "Password change is not required for this user",
			})
			return
		}

		// API request - return JSON error
		c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
			"password_change_not_required",
			"Password change is not required for this user",
		))
		return
	}

	// Get password requirements
	minLength, requiredCharClasses, err := h.db.GetPasswordSettings(ctx)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to get password settings")
		// Use defaults if settings can't be read
		minLength = 12
		requiredCharClasses = []string{"lowercase", "uppercase", "numbers"}
	}

	c.HTML(http.StatusOK, "password_change.html", gin.H{
		"user_id":               userID,
		"return_to":             returnTo,
		"title":                 "Change Password",
		"min_length":            minLength,
		"required_char_classes": requiredCharClasses,
	})
}

// ChangePassword handles password change requests
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	ctx := context.Background()

	var req requests.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.SecurityLog("invalid_password_change_request", 0, c.ClientIP(), map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
			"invalid_request",
			"Invalid request format",
		))
		return
	}

	var userID int
	var user *database.User

	// Check if user has an existing session
	sessionData, hasSession := c.Get("session_data")
	if hasSession {
		// User is already authenticated, use session user ID
		userID = sessionData.(*session.SessionData).UserID

		// Get user information
		var err error
		user, err = h.db.GetUserByID(ctx, userID)
		if err != nil {
			h.logger.SecurityLog("password_change_user_lookup_failed", userID, c.ClientIP(), map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusInternalServerError, responses.NewErrorResponse(
				"server_error",
				"Failed to verify user",
			))
			return
		}
	} else {
		// No session - this is a forced password change during login
		if req.UserID == 0 {
			c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
				"invalid_request",
				"User ID is required for password change without session",
			))
			return
		}
		userID = req.UserID

		// Get user information
		var err error
		user, err = h.db.GetUserByID(ctx, userID)
		if err != nil {
			h.logger.SecurityLog("password_change_user_lookup_failed", userID, c.ClientIP(), map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusNotFound, responses.NewErrorResponse(
				"user_not_found",
				"User not found",
			))
			return
		}

		// Verify user actually needs to change password
		if !user.MustChangePassword {
			c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
				"password_change_not_required",
				"Password change is not required for this user",
			))
			return
		}
	}

	// Validate passwords match
	if req.NewPassword != req.ConfirmPassword {
		h.logger.SecurityLog("password_change_mismatch", userID, c.ClientIP(), nil)
		c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
			"password_mismatch",
			"New password and confirmation do not match",
		))
		return
	}

	// Verify current password
	_, err := h.db.AuthenticateUser(ctx, user.Login, req.CurrentPassword)
	if err != nil {
		h.logger.SecurityLog("password_change_current_invalid", userID, c.ClientIP(), map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusBadRequest, responses.NewErrorResponse(
			"invalid_current_password",
			"Current password is incorrect",
		))
		return
	}

	// Change password
	err = h.db.ChangePassword(ctx, userID, req.NewPassword)
	if err != nil {
		h.logger.SecurityLog("password_change_failed", userID, c.ClientIP(), map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusInternalServerError, responses.NewErrorResponse(
			"password_change_failed",
			"Failed to change password",
		))
		return
	}

	h.logger.SecurityLog("password_change_success", userID, c.ClientIP(), nil)

	// If this was a forced password change (no session), create a session now
	if !hasSession {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		// Try to get return_to from temp session
		returnTo := ""
		tempSessionToken, err := c.Cookie("temp_session")
		if err == nil && tempSessionToken != "" {
			ctx := context.Background()
			returnTo, _ = h.redis.Get(ctx, "temp_return_to:"+tempSessionToken).Result()
			// Clean up temp data
			h.redis.Del(ctx, "temp_return_to:"+tempSessionToken)
		}

		// Check if 2FA is enabled at the gateway level and user has it configured
		if h.checkAndEnforceTwoFactor(c, user) {
			return
		}

		// No 2FA required, create regular auth session
		sessionToken, csrfToken, err := h.sessionManager.CreateSessionWithReturnTo(user.ID, user.Login, clientIP, userAgent, returnTo)
		if err != nil {
			h.logger.Logger.WithField("error", err.Error()).Error("Failed to create session after password change")
			c.JSON(http.StatusInternalServerError, responses.NewErrorResponse(
				"server_error",
				"Password changed but failed to create session",
			))
			return
		}

		// Set secure cookie
		c.SetSameSite(http.SameSiteStrictMode)
		c.SetCookie(
			"auth_session", // name
			sessionToken,   // value
			900,            // maxAge (15 minutes)
			"/",            // path
			"",             // domain
			true,           // secure (HTTPS only)
			true,           // httpOnly
		)

		c.JSON(http.StatusOK, responses.AuthResponse{
			Authenticated: true,
			SessionToken:  sessionToken,
			UserID:        user.ID,
			ExpiresIn:     900,
			CSRFToken:     csrfToken,
		})
		return
	}

	// Normal password change response
	c.JSON(http.StatusOK, responses.PasswordChangeResponse{
		Success: true,
		Message: "Password changed successfully",
	})
}

// SessionAuthMiddleware validates session and sets user context
func (h *AuthHandler) SessionAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionToken, err := c.Cookie("auth_session")
		if err != nil {
			c.JSON(http.StatusUnauthorized, responses.NewErrorResponse(
				"unauthorized",
				"Valid session required",
			))
			c.Abort()
			return
		}

		sessionData, err := h.sessionManager.ValidateSession(sessionToken, c.ClientIP(), c.GetHeader("User-Agent"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, responses.NewErrorResponse(
				"unauthorized",
				"Invalid or expired session",
			))
			c.Abort()
			return
		}

		// Set session data in context for handlers
		c.Set("session_data", sessionData)
		c.Next()
	}
}
