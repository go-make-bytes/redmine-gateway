package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"a_go_oauth/internal/config"
	"a_go_oauth/internal/database"
	"a_go_oauth/internal/logger"
	"a_go_oauth/internal/middleware"
	"a_go_oauth/internal/session"
)

// AuthHandler handles secure authentication endpoints
type AuthHandler struct {
	cfg            *config.Config
	db             *database.PostgreSQL
	logger         *logger.Logger
	sessionManager *session.SessionManager
	validator      *middleware.InputValidator
	csrfProtection *middleware.CSRFProtection
}

// AuthRequest represents authentication request
type AuthRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	Authenticated bool   `json:"authenticated"`
	SessionToken  string `json:"session_token,omitempty"`
	UserID        int    `json:"user_id,omitempty"`
	ExpiresIn     int    `json:"expires_in"`
	CSRFToken     string `json:"csrf_token,omitempty"`
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(
	cfg *config.Config,
	db *database.PostgreSQL,
	logger *logger.Logger,
	sessionManager *session.SessionManager,
	validator *middleware.InputValidator,
	csrfProtection *middleware.CSRFProtection,
) *AuthHandler {
	return &AuthHandler{
		cfg:            cfg,
		db:             db,
		logger:         logger,
		sessionManager: sessionManager,
		validator:      validator,
		csrfProtection: csrfProtection,
	}
}

// Login handles secure authentication
func (h *AuthHandler) Login(c *gin.Context) {
	ctx := context.Background()

	var req AuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.SecurityLog("invalid_auth_request", 0, c.ClientIP(), map[string]interface{}{
			"error": err.Error(),
		})

		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request format",
		})
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

		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
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

		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_credentials",
			"error_description": "Invalid username or password",
		})
		return
	}

	// Create secure session
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	sessionToken, csrfToken, err := h.sessionManager.CreateSession(user.ID, user.Login, clientIP, userAgent)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to create session")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to create session",
		})
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

	c.JSON(http.StatusOK, AuthResponse{
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
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "no_session",
			"error_description": "No active session found",
		})
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

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// CheckSession validates current session
func (h *AuthHandler) CheckSession(c *gin.Context) {
	sessionToken, err := c.Cookie("auth_session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"authenticated": false,
			"error":         "no_session",
		})
		return
	}

	sessionData, err := h.sessionManager.ValidateSession(sessionToken, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"authenticated": false,
			"error":         "invalid_session",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"user_id":       sessionData.UserID,
		"username":      sessionData.Username,
		"expires_in":    int(time.Until(sessionData.LastAccessed.Add(15 * time.Minute)).Seconds()),
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
