package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
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
	logger          *logger.Logger
	config          *config.Config
}

// NewTwoFAHandler creates a new 2FA handler
func NewTwoFAHandler(
	db *database.PostgreSQL,
	twoFASessionMgr *session.TwoFASessionManager,
	sessionManager *session.SessionManager,
	totpService *twofa.TOTPService,
	logger *logger.Logger,
	cfg *config.Config,
) *TwoFAHandler {
	return &TwoFAHandler{
		db:              db,
		twoFASessionMgr: twoFASessionMgr,
		sessionManager:  sessionManager,
		totpService:     totpService,
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
		h.logger.Warn("2FA verification attempted on locked account",
			"user_id", sessionData.UserID,
			"username", sessionData.Username,
		)
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
			h.logger.Info("Successful 2FA verification with backup code",
				"user_id", sessionData.UserID,
				"username", sessionData.Username,
			)
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

		// Decrypt TOTP secret
		secret, err := h.totpService.DecryptSecret(twoFAData.TOTPKey.String)
		if err != nil {
			h.logger.Error("Failed to decrypt TOTP secret", "error", err, "user_id", sessionData.UserID)
			c.JSON(http.StatusInternalServerError, responses.ErrorResponse{
				Error:            "internal_error",
				ErrorDescription: "Failed to verify TOTP code",
			})
			return
		}

		// Validate TOTP code
		valid = h.totpService.ValidateCode(secret, req.Code)
		if valid {
			// Update last used timestamp
			if err := h.db.UpdateTOTPLastUsed(ctx, sessionData.UserID); err != nil {
				h.logger.Error("Failed to update TOTP last used", "error", err, "user_id", sessionData.UserID)
				// Non-fatal error, continue
			}
			h.logger.Info("Successful 2FA verification with TOTP",
				"user_id", sessionData.UserID,
				"username", sessionData.Username,
			)
		}
	}

	if !valid {
		// Increment failed attempts
		attempts, err := h.twoFASessionMgr.TrackTwoFAAttempts(ctx, req.SessionToken)
		if err != nil {
			h.logger.Error("Failed to track 2FA attempts", "error", err)
		}

		h.logger.Warn("Failed 2FA verification attempt",
			"user_id", sessionData.UserID,
			"username", sessionData.Username,
			"attempts", attempts,
		)

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

	// Create regular session after successful 2FA
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

	h.logger.Info("2FA verification successful, session created",
		"user_id", sessionData.UserID,
		"username", sessionData.Username,
		"session_id", sessionToken,
	)

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

	// Return success with session information
	c.JSON(http.StatusOK, responses.TwoFAVerifyResponse{
		Success: true,
		Message: "2FA verification successful",
		// TODO: Add AccessToken and RefreshToken when JWT generation is implemented
	})
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

	h.logger.Info("2FA setup initiated",
		"event", "twofa_enrollment_setup",
		"user_id", sessionData.UserID,
		"username", sessionData.Username,
		"ip", clientIP,
		"timestamp", time.Now().Unix(),
	)

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

		h.logger.Warn("Failed 2FA confirmation attempt",
			"event", "twofa_enrollment_verify_failed",
			"user_id", sessionData.UserID,
			"username", sessionData.Username,
			"attempts", attempts,
			"ip", clientIP,
			"timestamp", time.Now().Unix(),
		)

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

	h.logger.Info("2FA enrollment completed successfully",
		"event", "twofa_enrollment_completed",
		"user_id", sessionData.UserID,
		"username", sessionData.Username,
		"ip", clientIP,
		"backup_codes_generated", len(backupCodes),
		"timestamp", time.Now().Unix(),
	)

	// Return success with backup codes (display once!)
	c.JSON(http.StatusOK, responses.TwoFAConfirmResponse{
		Success:     true,
		BackupCodes: backupCodes,
		Message:     "2FA enabled successfully. Save your backup codes in a secure location.",
	})
}

// TwoFADisable disables 2FA for a user
func (h *TwoFAHandler) TwoFADisable(c *gin.Context) {
	// TODO: Implement in Phase 6 (Management)
	c.JSON(http.StatusNotImplemented, responses.ErrorResponse{
		Error:            "not_implemented",
		ErrorDescription: "2FA disable endpoint not yet implemented",
	})
}

// TwoFAStatus returns current 2FA status for a user
func (h *TwoFAHandler) TwoFAStatus(c *gin.Context) {
	// TODO: Implement in Phase 6 (Management)
	c.JSON(http.StatusNotImplemented, responses.ErrorResponse{
		Error:            "not_implemented",
		ErrorDescription: "2FA status endpoint not yet implemented",
	})
}

// BackupCodesGenerate generates new backup codes for a user
func (h *TwoFAHandler) BackupCodesGenerate(c *gin.Context) {
	// TODO: Implement in Phase 6 (Management)
	c.JSON(http.StatusNotImplemented, responses.ErrorResponse{
		Error:            "not_implemented",
		ErrorDescription: "Backup codes generate endpoint not yet implemented",
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
	})
}

// ShowTwoFAEnrollPage displays the 2FA enrollment page
func (h *TwoFAHandler) ShowTwoFAEnrollPage(c *gin.Context) {
	token := c.Query("token")

	if token == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":   "Missing Token",
			"message": "2FA session token is required. Please login again.",
		})
		return
	}

	c.HTML(http.StatusOK, "twofa_enroll.html", gin.H{
		"token": token,
	})
}
