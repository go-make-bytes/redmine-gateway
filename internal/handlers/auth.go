package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	internalldap "github.com/go-make-bytes/redmine-gateway/internal/ldap"
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
func (h *AuthHandler) checkAndEnforceTwoFactor(c *gin.Context, user *database.User, authMethod string, authSourceID *int) bool {
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

	// Check if user has 2FA enabled (checks both OSS and Easy platforms)
	has2FA, err := h.db.HasTwoFactorEnabled(ctx, user.ID)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to check 2FA status")
		c.JSON(http.StatusInternalServerError, responses.NewErrorResponse(
			"server_error",
			"Failed to verify 2FA status",
		))
		return true // Stop processing
	}

	// When TWOFA_ENABLED=true, all users must have 2FA
	// Determine if user needs to enroll or verify
	hasTotp := twoFAData.Scheme.Valid && twoFAData.Scheme.String == "totp"
	enrollmentMode := !has2FA

	// Log platform-specific information
	platformInfo := h.db.GetPlatformInfo()
	h.logger.Logger.WithFields(map[string]interface{}{
		"user_id":         user.ID,
		"username":        user.Login,
		"platform":        string(platformInfo.Platform),
		"has_oss_2fa":     hasTotp,
		"has_2fa":         has2FA,
		"enrollment_mode": enrollmentMode,
	}).Debug("2FA check for user")

	// Extract client IP
	clientIP := h.twoFASessionMgr.ExtractClientIP(c.ClientIP(), c.GetHeader("X-Forwarded-For"))

	// Create temporary 2FA session
	twoFAToken, err := h.twoFASessionMgr.CreateTwoFASession(ctx, user.ID, user.Login, clientIP, enrollmentMode, authMethod, authSourceID)
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
		"platform":        string(platformInfo.Platform),
		"auth_method":     authMethod,
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

	var user *database.User
	var err error
	var authMethod string
	var authSourceID *int

	// Try LDAP authentication first if LDAP sources are configured
	ldapSources, err := h.db.GetActiveLDAPSources()
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Warn("Failed to retrieve LDAP sources")
		ldapSources = nil // Continue with database auth
	}

	if len(ldapSources) > 0 {
		user, authSourceID, err = h.authenticateLDAP(ctx, req.Username, req.Password, ldapSources, c.ClientIP())
		if err == nil {
			authMethod = "ldap"
		} else {
			h.logger.Logger.WithFields(map[string]interface{}{
				"username": req.Username,
				"error":    err.Error(),
			}).Debug("LDAP authentication failed, will try database auth")
		}
	}

	// If LDAP authentication failed or no LDAP sources configured, try database authentication
	// Only for users without LDAP linkage (T025/T026: prevent database fallback for LDAP users)
	if user == nil {
		// Check if this username exists with LDAP linkage
		// If so, they MUST authenticate via LDAP (no database password fallback)
		if len(ldapSources) > 0 {
			// Check each LDAP source to see if user exists with that auth_source_id
			for _, source := range ldapSources {
				existingUser, err := h.db.FindUserByLoginAndAuthSource(req.Username, source.ID)
				if err == nil && existingUser != nil {
					// User exists with LDAP linkage - reject database fallback
					h.logger.SecurityLog("authentication_failed", existingUser.ID, c.ClientIP(), map[string]interface{}{
						"username":       req.Username,
						"auth_source_id": source.ID,
						"reason":         "LDAP user failed LDAP authentication, database fallback not allowed",
					})

					c.JSON(http.StatusUnauthorized, responses.NewErrorResponse(
						"invalid_credentials",
						"Invalid username or password",
					))
					return
				}
			}
		}

		// No LDAP linkage found - try database authentication
		user, err = h.db.AuthenticateUser(ctx, req.Username, req.Password)
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
		authMethod = "database"
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
	if h.checkAndEnforceTwoFactor(c, user, authMethod, authSourceID) {
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
		"username":       user.Login,
		"session_id":     sessionToken,
		"auth_method":    authMethod,
		"auth_source_id": authSourceID,
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
		AuthSourceID:  authSourceID,
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
		"base_path": h.cfg.Server.BasePath,
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
		"base_path":             h.cfg.Server.BasePath,
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
		// Password change always uses database auth method
		if h.checkAndEnforceTwoFactor(c, user, "database", nil) {
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

// authenticateLDAP attempts LDAP bind for the user against configured LDAP sources
// Returns user, auth_source_id, and error
func (h *AuthHandler) authenticateLDAP(ctx context.Context, username, password string, ldapSources []database.LDAPAuthSource, clientIP string) (*database.User, *int, error) {
	// Try each LDAP source sequentially (ordered by ID)
	for _, source := range ldapSources {
		h.logger.Logger.WithFields(map[string]interface{}{
			"ldap_source_id":   source.ID,
			"ldap_source_name": source.Name,
			"username":         username,
		}).Debug("Attempting LDAP bind")

		// Create LDAP client
		ldapClient := internalldap.NewClient(
			source.Host,
			source.Port,
			source.TLS,
			h.cfg.LDAP.ConnectionTimeout,
		)

		// Prepare attributes to retrieve
		attributesToRetrieve := []string{
			source.AttrLogin,
			source.AttrMail,
		}
		if source.AttrFirstname != "" {
			attributesToRetrieve = append(attributesToRetrieve, source.AttrFirstname)
		}
		if source.AttrLastname != "" {
			attributesToRetrieve = append(attributesToRetrieve, source.AttrLastname)
		}

		// Attempt LDAP bind
		attributes, err := ldapClient.AuthenticateUser(
			source.BaseDN,
			source.AttrLogin,
			username,
			password,
			source.Account,
			source.AccountPassword,
			source.Filter,
			attributesToRetrieve,
		)

		if err != nil {
			h.logger.Logger.WithFields(map[string]interface{}{
				"ldap_source_id": source.ID,
				"username":       username,
				"error":          err.Error(),
			}).Debug("LDAP bind failed for this source")
			continue // Try next LDAP source
		}

		// LDAP bind successful - extract attributes
		login := attributes[source.AttrLogin]
		mail := attributes[source.AttrMail]
		firstname := attributes[source.AttrFirstname]
		lastname := attributes[source.AttrLastname]

		// Required attributes check
		if login == "" || mail == "" {
			h.logger.Logger.WithFields(map[string]interface{}{
				"ldap_source_id": source.ID,
				"username":       username,
			}).Warn("LDAP bind succeeded but required attributes missing")
			continue
		}

		h.logger.SecurityLog("ldap_bind_success", 0, clientIP, map[string]interface{}{
			"username":         username,
			"ldap_source_id":   source.ID,
			"ldap_source_name": source.Name,
		})

		// Check if user exists in Redmine
		user, err := h.db.FindUserByLoginAndAuthSource(login, source.ID)
		if err != nil {
			h.logger.Logger.WithField("error", err.Error()).Error("Failed to find user by login and auth source")
			return nil, nil, err
		}

		if user == nil {
			// Create new user (on-the-fly registration)
			if !source.OnTheFlyRegister {
				h.logger.Logger.WithFields(map[string]interface{}{
					"ldap_source_id": source.ID,
					"username":       login,
				}).Warn("On-the-fly registration disabled for this LDAP source")
				continue
			}

			user, err = h.db.CreateLDAPUser(login, firstname, lastname, mail, source.ID)
			if err != nil {
				h.logger.Logger.WithField("error", err.Error()).Error("Failed to create LDAP user")
				return nil, nil, err
			}

			h.logger.SecurityLog("ldap_user_created", user.ID, clientIP, map[string]interface{}{
				"username":         login,
				"ldap_source_id":   source.ID,
				"ldap_source_name": source.Name,
			})
		} else {
			// Update existing user attributes
			err = h.db.UpdateLDAPUserAttributes(user.ID, firstname, lastname, mail)
			if err != nil {
				h.logger.Logger.WithField("error", err.Error()).Warn("Failed to update LDAP user attributes")
				// Continue anyway - auth succeeded
			} else {
				h.logger.Logger.WithField("user_id", user.ID).Debug("Updated LDAP user attributes")
			}
		}

		return user, &source.ID, nil
	}

	// All LDAP sources failed
	h.logger.SecurityLog("ldap_bind_failure", 0, clientIP, map[string]interface{}{
		"username":      username,
		"sources_tried": len(ldapSources),
	})

	return nil, nil, fmt.Errorf("LDAP bind failed for all configured sources")
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
