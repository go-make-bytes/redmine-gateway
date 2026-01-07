package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/oauth"
	"github.com/go-make-bytes/redmine-gateway/internal/router/requests"
	"github.com/go-make-bytes/redmine-gateway/internal/router/responses"
	"github.com/go-make-bytes/redmine-gateway/internal/session"
	"github.com/go-make-bytes/redmine-gateway/internal/twofa"
)

// TwoFAHandler handles Two-Factor Authentication operations
type TwoFAHandler struct {
	db              *database.PostgreSQL
	twoFASessionMgr *session.TwoFASessionManager
	sessionManager  *session.SessionManager
	totpService     *twofa.TOTPService
	oauthProvider   *oauth.Provider
	logger          *logger.Logger
	config          *config.Config
}

// NewTwoFAHandler creates a new 2FA handler
func NewTwoFAHandler(
	db *database.PostgreSQL,
	twoFASessionMgr *session.TwoFASessionManager,
	sessionManager *session.SessionManager,
	totpService *twofa.TOTPService,
	oauthProvider *oauth.Provider,
	logger *logger.Logger,
	cfg *config.Config,
) *TwoFAHandler {
	return &TwoFAHandler{
		db:              db,
		twoFASessionMgr: twoFASessionMgr,
		sessionManager:  sessionManager,
		totpService:     totpService,
		oauthProvider:   oauthProvider,
		logger:          logger,
		config:          cfg,
	}
}

// TwoFAVerify handles 2FA code verification (TOTP or backup code)
func (h *TwoFAHandler) TwoFAVerify(c *gin.Context) {
	var req requests.TwoFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid 2FA verify request", "error", err)
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request format",
		})
		return
	}

	ctx := c.Request.Context()

	// Extract client IP
	clientIP := h.twoFASessionMgr.ExtractClientIP(c.ClientIP(), c.GetHeader("X-Forwarded-For"))

	// Validate 2FA session
	sessionData, err := h.twoFASessionMgr.ValidateTwoFASession(ctx, req.SessionToken, clientIP)
	if err != nil {
		h.logger.Warn("Invalid 2FA session", "error", err, "ip", clientIP)
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "invalid_session",
			ErrorDescription: "2FA session expired or invalid",
		})
		return
	}

	// Check if this is an enrollment session (enrollment sessions cannot be used for verification)
	if sessionData.EnrollmentMode {
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "not_verification_mode",
			ErrorDescription: "This session is in enrollment mode and cannot be used for verification",
		})
		return
	}

	// Check if account is locked
	locked, err := h.twoFASessionMgr.IsAccountLocked(ctx, sessionData.UserID)
	if err != nil {
		h.logger.Error("Failed to check account lock status", "error", err, "user_id", sessionData.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to verify 2FA code",
		})
		return
	}
	if locked {
		lockoutExpiry, _ := h.twoFASessionMgr.GetLockoutExpiry(ctx, sessionData.UserID)
		h.logger.Logger.WithFields(logrus.Fields{
			"user_id":  sessionData.UserID,
			"username": sessionData.Username,
		}).Warn("2FA verification attempted on locked account")
		c.JSON(http.StatusTooManyRequests, responses.ErrorResponse{
			Error:            "account_locked",
			ErrorDescription: "Too many failed attempts. Please try again later.",
			Details: map[string]interface{}{
				"locked_until": lockoutExpiry.Seconds(),
			},
		})
		return
	}

	// Get user's 2FA data
	twoFAData, err := h.db.GetUserTwoFactorData(ctx, sessionData.UserID)
	if err != nil {
		h.logger.Error("Failed to get 2FA data", "error", err, "user_id", sessionData.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to verify 2FA code",
		})
		return
	}

	var valid bool

	// Determine if backup code or TOTP
	if req.IsBackupCode || len(req.Code) == h.config.TwoFactor.BackupCode.Length {
		// Validate backup code format (8 characters, alphanumeric)
		if len(req.Code) != h.config.TwoFactor.BackupCode.Length || !isValidBackupCodeFormat(req.Code) {
			h.logger.Warn("Invalid backup code format", "user_id", sessionData.UserID, "code_length", len(req.Code))
			c.JSON(http.StatusBadRequest, responses.ErrorResponse{
				Error:            "invalid_backup_code_format",
				ErrorDescription: "Backup code must be 8 alphanumeric characters",
			})
			return
		}

		// Validate backup code
		valid, err = h.db.ValidateAndConsumeBackupCode(ctx, sessionData.UserID, req.Code)
		if err != nil {
			h.logger.Error("Failed to validate backup code", "error", err, "user_id", sessionData.UserID)
			c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
				Error:            "internal_error",
				ErrorDescription: "Failed to verify backup code",
			})
			return
		}
		if valid {
			h.logger.TwoFAVerificationAudit(sessionData.UserID, sessionData.Username, clientIP, true, "backup_code", map[string]interface{}{})
		}
	} else {
		// Validate TOTP code
		if !twoFAData.TOTPKey.Valid {
			h.logger.Error("TOTP key not configured", "user_id", sessionData.UserID)
			c.JSON(http.StatusBadRequest, responses.ErrorResponse{
				Error:            "totp_not_configured",
				ErrorDescription: "TOTP is not configured for this user",
			})
			return
		}

		// Use platform-aware TOTP validation (handles both OSS and Easy)
		valid, err = h.totpService.ValidateTOTPWithPlatformDetection(
			ctx,
			h.db,
			sessionData.UserID,
			req.Code,
			twoFAData.TOTPKey.String,
		)
		if err != nil {
			h.logger.Error("Failed to validate TOTP code", "error", err, "user_id", sessionData.UserID)
			c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
				Error:            "internal_error",
				ErrorDescription: "Failed to verify TOTP code",
			})
			return
		}

		if valid {
			h.logger.TwoFAVerificationAudit(sessionData.UserID, sessionData.Username, clientIP, true, "totp", map[string]interface{}{})
		}
	}

	if !valid {
		// Increment failed attempts
		attempts, err := h.twoFASessionMgr.TrackTwoFAAttempts(ctx, req.SessionToken)
		if err != nil {
			h.logger.Error("Failed to track 2FA attempts", "error", err)
		}

		h.logger.TwoFAVerificationAudit(sessionData.UserID, sessionData.Username, clientIP, false, "unknown", map[string]interface{}{
			"attempts": attempts,
		})

		// Check if max attempts reached
		if attempts >= h.config.TwoFactor.MaxAttempts {
			// Lock account
			if err := h.twoFASessionMgr.LockAccount(ctx, sessionData.UserID); err != nil {
				h.logger.Error("Failed to lock account", "error", err, "user_id", sessionData.UserID)
			}
			// Destroy session
			if err := h.twoFASessionMgr.DestroyTwoFASession(ctx, req.SessionToken); err != nil {
				h.logger.Error("Failed to destroy 2FA session", "error", err)
			}

			c.JSON(http.StatusTooManyRequests, responses.ErrorResponse{
				Error:            "max_attempts_exceeded",
				ErrorDescription: "Maximum verification attempts exceeded. Account locked for 1 hour.",
			})
			return
		}

		// Return error with remaining attempts
		remainingAttempts := h.config.TwoFactor.MaxAttempts - attempts
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "invalid_code",
			ErrorDescription: "Invalid verification code",
			Details: map[string]interface{}{
				"attempts_remaining": remainingAttempts,
			},
		})
		return
	}

	// Valid code - destroy 2FA session and create regular session
	if err := h.twoFASessionMgr.DestroyTwoFASession(ctx, req.SessionToken); err != nil {
		h.logger.Error("Failed to destroy 2FA session", "error", err)
		// Non-fatal, continue
	}

	// Create regular session after successful 2FA (for backward compatibility with cookie-based auth)
	userAgent := c.GetHeader("User-Agent")
	sessionToken, _, err := h.sessionManager.CreateSession(sessionData.UserID, sessionData.Username, clientIP, userAgent)
	if err != nil {
		h.logger.Error("Failed to create session after 2FA", "error", err, "user_id", sessionData.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to create session",
		})
		return
	}

	// Issue OAuth tokens for API access
	tokenResponse, err := h.oauthProvider.IssueTokensForUser(
		ctx,
		sessionData.UserID,
		"redmine-gateway-client", // Default client ID for direct auth
		"read write",             // Full scope for authenticated user
	)
	if err != nil {
		h.logger.Error("Failed to issue OAuth tokens after 2FA", "error", err, "user_id", sessionData.UserID)
		// Non-fatal - session still works, but API tokens won't be available
		h.logger.Warn("Continuing without OAuth tokens", "user_id", sessionData.UserID)
	}

	// TODO review data in log for successful 2FA verification with session and token issuance
	h.logger.Logger.WithFields(logrus.Fields{
		"user_id":       sessionData.UserID,
		"username":      sessionData.Username,
		"session_id":    sessionToken,
		"tokens_issued": tokenResponse != nil,
	}).Info("2FA verification successful, session and tokens created")

	// Set secure cookie (for web-based access)
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

	// Prepare response
	response := responses.TwoFAVerifyResponse{
		Success: true,
		Message: "2FA verification successful",
	}

	// Add OAuth tokens if successfully issued
	if tokenResponse != nil {
		response.AccessToken = tokenResponse.AccessToken
		response.RefreshToken = tokenResponse.RefreshToken
	}

	// Return success with session information and OAuth tokens
	c.JSON(http.StatusOK, response)
}

// TwoFASetup initiates 2FA setup for a user
// This endpoint handles both showing the HTML page and returning setup data as JSON
func (h *TwoFAHandler) TwoFASetup(c *gin.Context) {
	ctx := c.Request.Context()

	// Extract client IP
	clientIP := h.twoFASessionMgr.ExtractClientIP(c.ClientIP(), c.GetHeader("X-Forwarded-For"))

	// Get session token from query parameter or header
	sessionToken := c.Query("token")
	if sessionToken == "" {
		sessionToken = c.GetHeader("X-2FA-Session-Token")
	}

	if sessionToken == "" {
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "missing_token",
			ErrorDescription: "2FA session token is required",
		})
		return
	}

	// Validate 2FA session (must be in enrollment mode)
	sessionData, err := h.twoFASessionMgr.ValidateTwoFASession(ctx, sessionToken, clientIP)
	if err != nil {
		h.logger.Warn("Invalid 2FA session for setup", "error", err, "ip", clientIP)
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "invalid_session",
			ErrorDescription: "2FA session expired or invalid",
		})
		return
	}

	if !sessionData.EnrollmentMode {
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "not_enrollment_mode",
			ErrorDescription: "This session is not in enrollment mode",
		})
		return
	}

	// Generate new TOTP secret
	key, err := h.totpService.GenerateSecret(sessionData.Username)
	if err != nil {
		h.logger.Error("Failed to generate TOTP secret", "error", err, "user_id", sessionData.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to generate 2FA secret",
		})
		return
	}

	// Generate QR code
	qrCodeURL, err := h.totpService.GenerateQRCodeURL(key)
	if err != nil {
		h.logger.Error("Failed to generate QR code", "error", err, "user_id", sessionData.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to generate QR code",
		})
		return
	}

	// Store the secret temporarily in session data (for verification during confirm)
	// In production, you might want to store this encrypted in Redis
	// For now, we'll return it and expect the client to send it back during confirm

	h.logger.Logger.WithFields(logrus.Fields{
		"event":     "twofa_enrollment_setup",
		"user_id":   sessionData.UserID,
		"username":  sessionData.Username,
		"ip":        clientIP,
		"timestamp": time.Now().Unix(),
	}).Info("2FA setup initiated")

	c.JSON(http.StatusOK, responses.TwoFASetupResponse{
		Secret:    key.Secret(),
		QRCodeURL: qrCodeURL,
		Issuer:    h.config.TwoFactor.TOTP.Issuer,
		Account:   sessionData.Username,
	})
}

// TwoFAConfirm confirms 2FA setup with verification code
func (h *TwoFAHandler) TwoFAConfirm(c *gin.Context) {
	ctx := c.Request.Context()

	var req requests.TwoFAConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid 2FA confirm request", "error", err)
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request format",
		})
		return
	}

	// Extract client IP
	clientIP := h.twoFASessionMgr.ExtractClientIP(c.ClientIP(), c.GetHeader("X-Forwarded-For"))

	// Get session token from request
	sessionToken := c.GetHeader("X-2FA-Session-Token")
	if sessionToken == "" {
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "missing_token",
			ErrorDescription: "2FA session token is required",
		})
		return
	}

	// Validate 2FA session
	sessionData, err := h.twoFASessionMgr.ValidateTwoFASession(ctx, sessionToken, clientIP)
	if err != nil {
		h.logger.Warn("Invalid 2FA session for confirm", "error", err, "ip", clientIP)
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "invalid_session",
			ErrorDescription: "2FA session expired or invalid",
		})
		return
	}

	if !sessionData.EnrollmentMode {
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "not_enrollment_mode",
			ErrorDescription: "This session is not in enrollment mode",
		})
		return
	}

	// The secret should be passed in the request (from setup response)
	// In a more secure implementation, store it encrypted in Redis during setup
	if req.Secret == "" {
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "missing_secret",
			ErrorDescription: "TOTP secret is required",
		})
		return
	}

	// Validate the TOTP code with the secret
	valid := h.totpService.ValidateCode(req.Secret, req.Code)
	if !valid {
		// Track failed attempts
		attempts, err := h.twoFASessionMgr.TrackTwoFAAttempts(ctx, sessionToken)
		if err != nil {
			h.logger.Error("Failed to track 2FA attempts", "error", err)
		}

		h.logger.Logger.WithFields(logrus.Fields{
			"event":     "twofa_enrollment_verify_failed",
			"user_id":   sessionData.UserID,
			"username":  sessionData.Username,
			"attempts":  attempts,
			"ip":        clientIP,
			"timestamp": time.Now().Unix(),
		}).Warn("Failed 2FA confirmation attempt")

		// Check if max attempts reached
		if attempts >= h.config.TwoFactor.MaxAttempts {
			// Destroy session
			if err := h.twoFASessionMgr.DestroyTwoFASession(ctx, sessionToken); err != nil {
				h.logger.Error("Failed to destroy 2FA session", "error", err)
			}

			c.JSON(http.StatusTooManyRequests, responses.ErrorResponse{
				Error:            "max_attempts_exceeded",
				ErrorDescription: "Maximum verification attempts exceeded. Please start over.",
			})
			return
		}

		remainingAttempts := h.config.TwoFactor.MaxAttempts - attempts
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "invalid_code",
			ErrorDescription: "Invalid verification code",
			Details: map[string]interface{}{
				"attempts_remaining": remainingAttempts,
			},
		})
		return
	}

	// Code is valid - enable 2FA for the user
	// Encrypt the secret
	encryptedSecret, err := h.totpService.EncryptSecret(req.Secret)
	if err != nil {
		h.logger.Error("Failed to encrypt TOTP secret", "error", err, "user_id", sessionData.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to enable 2FA",
		})
		return
	}

	// Enable 2FA in database
	if err := h.db.EnableTwoFactor(ctx, sessionData.UserID, encryptedSecret); err != nil {
		h.logger.Error("Failed to enable 2FA", "error", err, "user_id", sessionData.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to enable 2FA",
		})
		return
	}

	// Generate backup codes
	backupCodes, err := h.db.GenerateBackupCodes(ctx, sessionData.UserID, h.config.TwoFactor.BackupCode.Count)
	if err != nil {
		h.logger.Error("Failed to generate backup codes", "error", err, "user_id", sessionData.UserID)
		// Non-fatal, 2FA is already enabled
		c.JSON(http.StatusOK, responses.TwoFAConfirmResponse{
			Success: true,
			Message: "2FA enabled successfully, but failed to generate backup codes. Please contact support.",
		})
		return
	}

	// Destroy 2FA session
	if err := h.twoFASessionMgr.DestroyTwoFASession(ctx, sessionToken); err != nil {
		h.logger.Error("Failed to destroy 2FA session", "error", err)
		// Non-fatal, continue
	}

	h.logger.TwoFAEnrollmentAudit(sessionData.UserID, sessionData.Username, clientIP, "completed", map[string]interface{}{
		"backup_codes_generated": len(backupCodes),
	})

	// Return success with backup codes (display once!)
	c.JSON(http.StatusOK, responses.TwoFAConfirmResponse{
		Success:     true,
		BackupCodes: backupCodes,
		Message:     "2FA enabled successfully. Save your backup codes in a secure location.",
	})
}

// TwoFADisable disables 2FA for a user
func (h *TwoFAHandler) TwoFADisable(c *gin.Context) {
	ctx := c.Request.Context()

	var req requests.TwoFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid 2FA disable request", "error", err)
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request format",
		})
		return
	}

	// Get user ID from session
	sessionData, exists := c.Get("session_data")
	if !exists {
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "unauthorized",
			ErrorDescription: "Valid session required",
		})
		return
	}

	userSession, ok := sessionData.(*session.SessionData)
	if !ok {
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Invalid session data",
		})
		return
	}

	// Get user's 2FA data to verify current setup
	twoFAData, err := h.db.GetUserTwoFactorData(ctx, userSession.UserID)
	if err != nil {
		h.logger.Error("Failed to get 2FA data for disable", "error", err, "user_id", userSession.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to verify 2FA status",
		})
		return
	}

	if !twoFAData.Scheme.Valid || twoFAData.Scheme.String != "totp" {
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "2fa_not_enabled",
			ErrorDescription: "2FA is not enabled for this account",
		})
		return
	}

	// Verify TOTP code before disabling
	if !twoFAData.TOTPKey.Valid {
		h.logger.Error("TOTP key missing for disable verification", "user_id", userSession.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "2FA configuration error",
		})
		return
	}

	// Decrypt secret
	secret, err := h.totpService.DecryptSecret(twoFAData.TOTPKey.String)
	if err != nil {
		h.logger.Error("Failed to decrypt TOTP secret for disable", "error", err, "user_id", userSession.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to verify TOTP code",
		})
		return
	}

	// Validate the provided TOTP code
	if !h.totpService.ValidateCode(secret, req.Code) {
		h.logger.Logger.WithFields(logrus.Fields{
			"user_id":  userSession.UserID,
			"username": userSession.Username,
		}).Warn("Invalid TOTP code provided for 2FA disable")
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "invalid_code",
			ErrorDescription: "Invalid TOTP code. 2FA disable cancelled.",
		})
		return
	}

	// Disable 2FA (this also deletes backup codes)
	if err := h.db.DisableTwoFactor(ctx, userSession.UserID); err != nil {
		h.logger.Error("Failed to disable 2FA", "error", err, "user_id", userSession.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to disable 2FA",
		})
		return
	}

	h.logger.TwoFAManagementAudit(userSession.UserID, userSession.Username, c.ClientIP(), "disable", nil)

	c.JSON(http.StatusOK, gin.H{
		"disabled": true,
		"message":  "Two-factor authentication has been disabled",
	})
}

// TwoFAStatus returns current 2FA status for a user
func (h *TwoFAHandler) TwoFAStatus(c *gin.Context) {
	ctx := c.Request.Context()

	// Get user ID from session
	sessionData, exists := c.Get("session_data")
	if !exists {
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "unauthorized",
			ErrorDescription: "Valid session required",
		})
		return
	}

	userSession, ok := sessionData.(*session.SessionData)
	if !ok {
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Invalid session data",
		})
		return
	}

	// Get 2FA data
	twoFAData, err := h.db.GetUserTwoFactorData(ctx, userSession.UserID)
	if err != nil {
		h.logger.Error("Failed to get 2FA data for status", "error", err, "user_id", userSession.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to retrieve 2FA status",
		})
		return
	}

	h.logger.Logger.WithFields(logrus.Fields{
		"user_id":  userSession.UserID,
		"username": userSession.Username,
		"enabled":  twoFAData.Scheme.Valid && twoFAData.Scheme.String == "totp",
	}).Info("2FA status requested")

	c.JSON(http.StatusOK, gin.H{
		"enabled":                twoFAData.Scheme.Valid && twoFAData.Scheme.String == "totp",
		"scheme":                 twoFAData.Scheme.String,
		"required":               twoFAData.Required,
		"backup_codes_remaining": twoFAData.BackupCodes,
	})
}

// BackupCodesGenerate generates new backup codes for a user
func (h *TwoFAHandler) BackupCodesGenerate(c *gin.Context) {
	ctx := c.Request.Context()

	var req requests.TwoFABackupCodesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid backup codes generate request", "error", err)
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request format",
		})
		return
	}

	// Get user ID from session
	sessionData, exists := c.Get("session_data")
	if !exists {
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "unauthorized",
			ErrorDescription: "Valid session required",
		})
		return
	}

	userSession, ok := sessionData.(*session.SessionData)
	if !ok {
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Invalid session data",
		})
		return
	}

	// Get user's 2FA data to verify current setup
	twoFAData, err := h.db.GetUserTwoFactorData(ctx, userSession.UserID)
	if err != nil {
		h.logger.Error("Failed to get 2FA data for backup codes", "error", err, "user_id", userSession.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to verify 2FA status",
		})
		return
	}

	if !twoFAData.Scheme.Valid || twoFAData.Scheme.String != "totp" {
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "2fa_not_enabled",
			ErrorDescription: "2FA must be enabled to generate backup codes",
		})
		return
	}

	// Verify TOTP code before generating new backup codes
	if !twoFAData.TOTPKey.Valid {
		h.logger.Error("TOTP key missing for backup codes generation", "user_id", userSession.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "2FA configuration error",
		})
		return
	}

	// Decrypt secret
	secret, err := h.totpService.DecryptSecret(twoFAData.TOTPKey.String)
	if err != nil {
		h.logger.Error("Failed to decrypt TOTP secret for backup codes", "error", err, "user_id", userSession.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to verify TOTP code",
		})
		return
	}

	// Validate the provided TOTP code
	if !h.totpService.ValidateCode(secret, req.Code) {
		h.logger.Logger.WithFields(logrus.Fields{
			"user_id":  userSession.UserID,
			"username": userSession.Username,
		}).Warn("Invalid TOTP code provided for backup codes generation")
		c.JSON(http.StatusUnauthorized, responses.ErrorResponse{
			Error:            "invalid_code",
			ErrorDescription: "Invalid TOTP code. Backup codes generation cancelled.",
		})
		return
	}

	// Generate new backup codes (this replaces existing ones)
	newBackupCodes, err := h.db.GenerateBackupCodes(ctx, userSession.UserID, h.config.TwoFactor.BackupCode.Count)
	if err != nil {
		h.logger.Error("Failed to generate backup codes", "error", err, "user_id", userSession.UserID)
		c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
			Error:            "internal_error",
			ErrorDescription: "Failed to generate backup codes",
		})
		return
	}

	h.logger.TwoFAManagementAudit(userSession.UserID, userSession.Username, c.ClientIP(), "backup_codes_regenerated", map[string]interface{}{
		"codes_generated": len(newBackupCodes),
	})

	c.JSON(http.StatusOK, gin.H{
		"backup_codes": newBackupCodes,
	})
}

// ShowTwoFAVerifyPage displays the 2FA verification page
func (h *TwoFAHandler) ShowTwoFAVerifyPage(c *gin.Context) {
	token := c.Query("token")
	maxAttempts := c.Query("max_attempts")

	if token == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":   "Missing Token",
			"message": "2FA session token is required. Please login again.",
		})
		return
	}

	c.HTML(http.StatusOK, "twofa_verify.html", gin.H{
		"token":        token,
		"max_attempts": maxAttempts,
		"base_path":    h.cfg.Server.BasePath,
	})
}

// ShowTwoFAEnrollPage displays the 2FA enrollment page
func (h *TwoFAHandler) ShowTwoFAEnrollPage(c *gin.Context) {
	token := c.Query("token")
	returnTo := c.Query("return_to")

	if token == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":   "Missing Token",
			"message": "2FA session token is required. Please login again.",
		})
		return
	}

	c.HTML(http.StatusOK, "twofa_enroll.html", gin.H{
		"token":     token,
		"return_to": returnTo,
		"base_path": h.cfg.Server.BasePath,
	})
}

// isValidBackupCodeFormat validates backup code format (8 alphanumeric characters)
func isValidBackupCodeFormat(code string) bool {
	if len(code) != 8 {
		return false
	}
	// Check if all characters are alphanumeric
	for _, r := range code {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
