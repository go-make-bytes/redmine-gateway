package twofa

import (
	"context"
	"fmt"
	"time"

	"github.com/go-make-bytes/redmine-gateway/internal/database"
)

// ValidateEasyTOTP validates TOTP code against Easy 2FA settings
// This method handles EasyRedmine-specific 2FA validation
func (s *TOTPService) ValidateEasyTOTP(ctx context.Context, db *database.PostgreSQL, userID int, code string) (bool, error) {
	// Get Easy 2FA scheme
	scheme, err := db.GetEasyTwofaScheme(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get 2FA scheme: %w", err)
	}
	if scheme == nil {
		return false, fmt.Errorf("no 2FA scheme found for user")
	}
	if !scheme.Activated {
		return false, fmt.Errorf("2FA not activated for user")
	}

	// Only support TOTP for now (SMS support not planned)
	if scheme.SchemeKey != "totp" {
		return false, fmt.Errorf("unsupported 2FA scheme: %s (only TOTP supported)", scheme.SchemeKey)
	}

	// Parse settings JSON to get TOTP key
	settings, err := database.ParseEasyTOTPSettings(scheme.Settings)
	if err != nil {
		return false, fmt.Errorf("failed to parse 2FA settings: %w", err)
	}

	// Decrypt the TOTP key if necessary
	// EasyRedmine may store the key encrypted, but for Phase 1 we assume plaintext
	// or handle decryption using the existing DecryptSecret method
	totpKey := settings.TOTPKey

	// Try to decrypt if it looks encrypted (base64)
	decryptedKey, err := s.DecryptSecret(totpKey)
	if err != nil {
		// If decryption fails, try using the key as-is
		decryptedKey = totpKey
	}

	// Validate TOTP code
	valid := s.ValidateCode(decryptedKey, code)
	if !valid {
		return false, nil // Invalid code, but not an error
	}

	// Update last used timestamp (optional - don't fail on error)
	if err := db.UpdateEasyTOTPLastUsed(ctx, userID, time.Now().Unix()); err != nil {
		// Log warning but don't fail the validation
		// This is non-critical metadata
		// Note: In production, you'd want to log this with proper logger
		_ = err // Suppress unused variable warning
	}

	return true, nil
}

// ValidateTOTPWithPlatformDetection validates TOTP code based on platform type
// This is the main entry point that routes to OSS or Easy validation
func (s *TOTPService) ValidateTOTPWithPlatformDetection(ctx context.Context, db *database.PostgreSQL, userID int, code string, encryptedSecret string) (bool, error) {
	platformInfo := db.GetPlatformInfo()

	// For EasyRedmine, check if user has Easy 2FA configured
	if platformInfo.Platform == database.PlatformEasy {
		easyScheme, err := db.GetEasyTwofaScheme(ctx, userID)
		if err != nil {
			return false, fmt.Errorf("failed to check Easy 2FA: %w", err)
		}

		// If user has Easy 2FA configured, use Easy validation
		if easyScheme != nil && easyScheme.Activated && easyScheme.SchemeKey == "totp" {
			return s.ValidateEasyTOTP(ctx, db, userID, code)
		}
	}

	// Fall back to OSS validation (users table twofa_totp_key)
	if encryptedSecret == "" {
		return false, fmt.Errorf("no TOTP secret configured for user")
	}

	// Decrypt the secret
	secret, err := s.DecryptSecret(encryptedSecret)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// Validate using standard OSS method
	return s.ValidateCode(secret, code), nil
}
