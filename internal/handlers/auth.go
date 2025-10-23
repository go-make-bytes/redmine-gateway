package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

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
) *AuthHandler {
	return &AuthHandler{
		cfg:             cfg,
		db:              db,
		logger:          logger,
		sessionManager:  sessionManager,
		twoFASessionMgr: twoFASessionMgr,
		validator:       validator,
		csrfProtection:  csrfProtection,
	}
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

	// Check if 2FA is enabled at the gateway level
	if h.cfg.TwoFactor.Enabled {
		// Get user's 2FA data to check if they have it configured
		twoFAData, err := h.db.GetUserTwoFactorData(ctx, user.ID)
		if err != nil {
			h.logger.Logger.WithField("error", err.Error()).Error("Failed to get 2FA data")
			c.JSON(http.StatusInternalServerError, responses.NewErrorResponse(
				"server_error",
				"Failed to verify 2FA status",
			))
			return
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
			return
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

	c.HTML(http.StatusOK, "secure_login.html", gin.H{
		"return_to": returnTo,
		"title":     "Secure Login",
	})
}
