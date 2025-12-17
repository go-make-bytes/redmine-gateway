package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// TwoFactorData represents 2FA configuration for a user
type TwoFactorData struct {
	Scheme      sql.NullString // "totp" or NULL
	TOTPKey     sql.NullString // Encrypted TOTP secret
	LastUsedAt  sql.NullInt64  // Unix timestamp
	Required    bool           // Whether 2FA is required for this user
	BackupCodes int            // Count of remaining backup codes
}

// GetUserTwoFactorData retrieves 2FA configuration for a user
// Platform-aware: uses OSS tables for Redmine OSS, Easy tables for EasyRedmine
func (p *PostgreSQL) GetUserTwoFactorData(ctx context.Context, userID int) (*TwoFactorData, error) {
	platformInfo := p.GetPlatformInfo()

	// For EasyRedmine, use Easy-specific 2FA tables
	if platformInfo.Platform == PlatformEasy {
		return p.getEasyTwoFactorData(ctx, userID)
	}

	// For OSS Redmine, use standard users table columns
	query := `
		SELECT 
			twofa_scheme, 
			twofa_totp_key, 
			twofa_totp_last_used_at,
			COALESCE(twofa_required, false) as twofa_required,
			(SELECT COUNT(*) FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code') as backup_codes_count
		FROM users 
		WHERE id = $1
	`

	var data TwoFactorData
	err := p.QueryRowContext(ctx, query, userID).Scan(
		&data.Scheme,
		&data.TOTPKey,
		&data.LastUsedAt,
		&data.Required,
		&data.BackupCodes,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found: %d", userID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query 2FA data: %w", err)
	}

	return &data, nil
}

// getEasyTwoFactorData retrieves 2FA data for EasyRedmine platform
func (p *PostgreSQL) getEasyTwoFactorData(ctx context.Context, userID int) (*TwoFactorData, error) {
	// Get Easy 2FA scheme
	scheme, err := p.GetEasyTwofaScheme(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Easy 2FA scheme: %w", err)
	}

	data := &TwoFactorData{
		Required:    false, // EasyRedmine doesn't have per-user required flag
		BackupCodes: 0,     // TODO: Check if Easy has backup codes
	}

	// If no scheme exists, return empty data (user has no 2FA)
	if scheme == nil {
		return data, nil
	}

	// Set scheme if TOTP is activated
	if scheme.Activated && scheme.SchemeKey == "totp" {
		data.Scheme = sql.NullString{String: "totp", Valid: true}

		// Parse settings to get TOTP key and last used timestamp
		var settings EasyTOTPSettings
		if scheme.Settings != "" && scheme.Settings != "{}" {
			if err := json.Unmarshal([]byte(scheme.Settings), &settings); err == nil {
				if settings.TOTPKey != "" {
					data.TOTPKey = sql.NullString{String: settings.TOTPKey, Valid: true}
				}
				if settings.TOTPLastUsedAt != nil {
					data.LastUsedAt = sql.NullInt64{Int64: *settings.TOTPLastUsedAt, Valid: true}
				}
			}
		}
	}

	return data, nil
}

// UpdateTOTPLastUsed updates the timestamp of last TOTP usage
func (p *PostgreSQL) UpdateTOTPLastUsed(ctx context.Context, userID int) error {
	query := `
		UPDATE users 
		SET twofa_totp_last_used_at = $1
		WHERE id = $2
	`

	now := time.Now().Unix()
	_, err := p.ExecContext(ctx, query, now, userID)
	if err != nil {
		return fmt.Errorf("failed to update TOTP last used timestamp: %w", err)
	}

	return nil
}

// HasTwoFactorEnabled checks if a user has 2FA configured
// Returns true if the user has a twofa_scheme set (currently only 'totp')
// For EasyRedmine, checks easy_twofa_user_schemes table
func (p *PostgreSQL) HasTwoFactorEnabled(ctx context.Context, userID int) (bool, error) {
	platformInfo := p.GetPlatformInfo()

	// For EasyRedmine, only check Easy 2FA table
	if platformInfo.Platform == PlatformEasy {
		return p.hasEasyTwoFactor(ctx, userID)
	}

	// For OSS Redmine, check users table
	return p.hasOSSTwoFactor(ctx, userID)
}

// hasOSSTwoFactor checks if user has OSS Redmine 2FA enabled
// Internal helper method
func (p *PostgreSQL) hasOSSTwoFactor(ctx context.Context, userID int) (bool, error) {
	query := `
		SELECT 
			COALESCE(twofa_scheme, '') as scheme
		FROM users 
		WHERE id = $1
	`

	var scheme string
	err := p.QueryRowContext(ctx, query, userID).Scan(&scheme)
	if err == sql.ErrNoRows {
		return false, fmt.Errorf("user not found: %d", userID)
	}
	if err != nil {
		return false, fmt.Errorf("failed to check 2FA status: %w", err)
	}

	// User has 2FA enabled if they have a scheme configured
	return scheme == "totp", nil
}

// IsTwoFactorRequired is kept for backward compatibility but now just calls HasTwoFactorEnabled
// The actual "required" logic (enrollment vs verification) is handled in the auth handler
func (p *PostgreSQL) IsTwoFactorRequired(ctx context.Context, userID int) (bool, error) {
	return p.HasTwoFactorEnabled(ctx, userID)
}

// GenerateBackupCodes generates and stores new backup codes for a user
// Returns the plaintext codes (display once to user)
// Note: Codes are stored in plain text to fit Redmine's tokens.value column (varchar(40))
// This follows Redmine's pattern for token storage (see app/models/token.rb)
func (p *PostgreSQL) GenerateBackupCodes(ctx context.Context, userID int, count int) ([]string, error) {
	// Delete existing backup codes
	deleteQuery := `DELETE FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code'`
	if _, err := p.ExecContext(ctx, deleteQuery, userID); err != nil {
		return nil, fmt.Errorf("failed to delete old backup codes: %w", err)
	}

	// Character set excluding ambiguous characters (0, O, I, l, 1)
	// Using a similar approach to Redmine's token generation
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codes := make([]string, count)

	// Generate and insert new codes
	insertQuery := `
		INSERT INTO tokens (user_id, action, value, created_on)
		VALUES ($1, 'twofa_backup_code', $2, $3)
	`

	for i := 0; i < count; i++ {
		// Generate random 8-character code (fits in varchar(40))
		// Format: XXXX-XXXX for better readability
		code := make([]byte, 8)
		for j := range code {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				return nil, fmt.Errorf("failed to generate random code: %w", err)
			}
			code[j] = charset[n.Int64()]
		}
		plainCode := string(code)

		// Store plaintext code (following Redmine's token storage pattern)
		// The tokens table is designed for plaintext tokens, not bcrypt hashes
		_, err := p.ExecContext(ctx, insertQuery, userID, plainCode, time.Now())
		if err != nil {
			return nil, fmt.Errorf("failed to insert backup code: %w", err)
		}

		codes[i] = plainCode
	}

	return codes, nil
}

// ValidateAndConsumeBackupCode validates a backup code and consumes it (single-use)
// Returns true if code was valid and consumed
// Note: Uses plaintext comparison following Redmine's token pattern
func (p *PostgreSQL) ValidateAndConsumeBackupCode(ctx context.Context, userID int, code string) (bool, error) {
	// Normalize input: remove any spaces or dashes
	code = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(code, " ", ""), "-", ""))

	// Try to find and delete the matching code in a single transaction
	deleteQuery := `
		DELETE FROM tokens 
		WHERE user_id = $1 
		  AND action = 'twofa_backup_code' 
		  AND value = $2
		RETURNING id
	`

	var tokenID int
	err := p.QueryRowContext(ctx, deleteQuery, userID, code).Scan(&tokenID)
	if err == sql.ErrNoRows {
		// No matching code found
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to validate and consume backup code: %w", err)
	}

	// Code was found and deleted
	return true, nil
}

// EnableTwoFactor enables TOTP 2FA for a user
// Platform-aware: uses OSS tables for Redmine OSS, Easy tables for EasyRedmine
func (p *PostgreSQL) EnableTwoFactor(ctx context.Context, userID int, encryptedSecret string) error {
	platformInfo := p.GetPlatformInfo()

	// For EasyRedmine, use Easy-specific 2FA tables
	if platformInfo.Platform == PlatformEasy {
		return p.EnableEasyTwoFactor(ctx, userID, encryptedSecret)
	}

	// For OSS Redmine, update users table
	query := `
		UPDATE users 
		SET twofa_scheme = 'totp',
		    twofa_totp_key = $1,
		    twofa_totp_last_used_at = NULL
		WHERE id = $2
	`

	_, err := p.ExecContext(ctx, query, encryptedSecret, userID)
	if err != nil {
		return fmt.Errorf("failed to enable 2FA: %w", err)
	}

	return nil
}

// DisableTwoFactor disables 2FA for a user and deletes backup codes
func (p *PostgreSQL) DisableTwoFactor(ctx context.Context, userID int) error {
	// Start transaction
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Clear 2FA settings
	updateQuery := `
		UPDATE users 
		SET twofa_scheme = NULL,
		    twofa_totp_key = NULL,
		    twofa_totp_last_used_at = NULL
		WHERE id = $1
	`
	if _, err := tx.ExecContext(ctx, updateQuery, userID); err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	// Delete backup codes
	deleteQuery := `DELETE FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code'`
	if _, err := tx.ExecContext(ctx, deleteQuery, userID); err != nil {
		return fmt.Errorf("failed to delete backup codes: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
