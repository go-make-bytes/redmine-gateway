package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// EasyTwofaScheme represents easy_twofa_user_schemes table in EasyRedmine
type EasyTwofaScheme struct {
	UserID    int       `json:"user_id"`
	Activated bool      `json:"activated"`
	SchemeKey string    `json:"scheme_key"` // "totp", "sms"
	Settings  string    `json:"settings"`   // JSON with TOTP settings
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EasyTOTPSettings represents the settings JSON stored in EasyRedmine
// Note: In EasyRedmine, these settings may be encrypted. For phase 1,
// we assume plaintext or handle decryption externally.
type EasyTOTPSettings struct {
	TOTPKey        string `json:"totp_key"`
	TOTPLastUsedAt *int64 `json:"totp_last_used_at,omitempty"`
}

// GetEasyTwofaScheme fetches Easy 2FA configuration for a user
// Returns nil if the table doesn't exist or user has no 2FA configured
func (p *PostgreSQL) GetEasyTwofaScheme(ctx context.Context, userID int) (*EasyTwofaScheme, error) {
	// Check if we're on EasyRedmine platform
	platformInfo := p.GetPlatformInfo()
	if platformInfo.Platform != PlatformEasy || !platformInfo.Has2FATable {
		return nil, nil // Not EasyRedmine or table doesn't exist
	}

	query := `
		SELECT user_id, activated, scheme_key, settings, created_at, updated_at
		FROM easy_twofa_user_schemes
		WHERE user_id = $1
	`

	var scheme EasyTwofaScheme
	err := p.QueryRowContext(ctx, query, userID).Scan(
		&scheme.UserID,
		&scheme.Activated,
		&scheme.SchemeKey,
		&scheme.Settings,
		&scheme.CreatedAt,
		&scheme.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil // No 2FA configured for this user
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query easy_twofa_user_schemes: %w", err)
	}

	return &scheme, nil
}

// hasEasyTwoFactor checks if a user has Easy 2FA enabled
// Internal helper method used by HasTwoFactorEnabled
func (p *PostgreSQL) hasEasyTwoFactor(ctx context.Context, userID int) (bool, error) {
	scheme, err := p.GetEasyTwofaScheme(ctx, userID)
	if err != nil {
		return false, err
	}

	// User has Easy 2FA if scheme exists, is activated, and is TOTP
	if scheme != nil && scheme.Activated && scheme.SchemeKey == "totp" {
		return true, nil
	}

	return false, nil
}

// UpdateEasyTOTPLastUsed updates the last used timestamp for Easy TOTP
// This updates the settings JSON field with the new timestamp
func (p *PostgreSQL) UpdateEasyTOTPLastUsed(ctx context.Context, userID int, timestamp int64) error {
	// Check if we're on EasyRedmine platform
	platformInfo := p.GetPlatformInfo()
	if platformInfo.Platform != PlatformEasy || !platformInfo.Has2FATable {
		return nil // Not EasyRedmine, skip update
	}

	// First, get the current scheme to access settings
	scheme, err := p.GetEasyTwofaScheme(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get Easy 2FA scheme: %w", err)
	}
	if scheme == nil {
		return fmt.Errorf("no Easy 2FA scheme found for user %d", userID)
	}

	// Parse existing settings
	var settings EasyTOTPSettings
	if scheme.Settings != "" && scheme.Settings != "{}" {
		if err := json.Unmarshal([]byte(scheme.Settings), &settings); err != nil {
			// If parsing fails, create new settings object
			settings = EasyTOTPSettings{}
		}
	}

	// Update the last used timestamp
	settings.TOTPLastUsedAt = &timestamp

	// Marshal back to JSON
	updatedSettings, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal updated settings: %w", err)
	}

	// Update the database
	query := `
		UPDATE easy_twofa_user_schemes 
		SET settings = $1, updated_at = NOW()
		WHERE user_id = $2
	`

	_, err = p.ExecContext(ctx, query, string(updatedSettings), userID)
	if err != nil {
		return fmt.Errorf("failed to update Easy TOTP last used: %w", err)
	}

	return nil
}

// ParseEasyTOTPSettings parses the settings JSON from EasyTwofaScheme
// This is a helper method to extract TOTP settings from the scheme
func ParseEasyTOTPSettings(settingsJSON string) (*EasyTOTPSettings, error) {
	if settingsJSON == "" || settingsJSON == "{}" {
		return nil, fmt.Errorf("empty settings JSON")
	}

	var settings EasyTOTPSettings
	if err := json.Unmarshal([]byte(settingsJSON), &settings); err != nil {
		return nil, fmt.Errorf("failed to parse Easy TOTP settings: %w", err)
	}

	if settings.TOTPKey == "" {
		return nil, fmt.Errorf("TOTP key not found in settings")
	}

	return &settings, nil
}
