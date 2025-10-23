package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/bcrypt"
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
func (p *PostgreSQL) GetUserTwoFactorData(ctx context.Context, userID int) (*TwoFactorData, error) {
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
func (p *PostgreSQL) HasTwoFactorEnabled(ctx context.Context, userID int) (bool, error) {
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
func (p *PostgreSQL) GenerateBackupCodes(ctx context.Context, userID int, count int) ([]string, error) {
	// Delete existing backup codes
	deleteQuery := `DELETE FROM tokens WHERE user_id = $1 AND action = 'twofa_backup_code'`
	if _, err := p.ExecContext(ctx, deleteQuery, userID); err != nil {
		return nil, fmt.Errorf("failed to delete old backup codes: %w", err)
	}

	// Character set excluding ambiguous characters (0, O, I, l, 1)
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codes := make([]string, count)

	// Generate and insert new codes
	insertQuery := `
		INSERT INTO tokens (user_id, action, value, created_on)
		VALUES ($1, 'twofa_backup_code', $2, $3)
	`

	for i := 0; i < count; i++ {
		// Generate random 12-character code
		code := make([]byte, 12)
		for j := range code {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				return nil, fmt.Errorf("failed to generate random code: %w", err)
			}
			code[j] = charset[n.Int64()]
		}
		plainCode := string(code)

		// Hash the code with bcrypt
		hashedCode, err := bcrypt.GenerateFromPassword([]byte(plainCode), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}

		// Store hashed code
		_, err = p.ExecContext(ctx, insertQuery, userID, string(hashedCode), time.Now())
		if err != nil {
			return nil, fmt.Errorf("failed to insert backup code: %w", err)
		}

		codes[i] = plainCode
	}

	return codes, nil
}

// ValidateAndConsumeBackupCode validates a backup code and consumes it (single-use)
// Returns true if code was valid and consumed
func (p *PostgreSQL) ValidateAndConsumeBackupCode(ctx context.Context, userID int, code string) (bool, error) {
	// Fetch all backup codes for the user
	query := `
		SELECT id, value 
		FROM tokens 
		WHERE user_id = $1 AND action = 'twofa_backup_code'
	`

	rows, err := p.QueryContext(ctx, query, userID)
	if err != nil {
		return false, fmt.Errorf("failed to query backup codes: %w", err)
	}
	defer rows.Close()

	// Check each hashed code
	for rows.Next() {
		var tokenID int
		var hashedCode string
		if err := rows.Scan(&tokenID, &hashedCode); err != nil {
			return false, fmt.Errorf("failed to scan backup code: %w", err)
		}

		// Compare with bcrypt
		if err := bcrypt.CompareHashAndPassword([]byte(hashedCode), []byte(code)); err == nil {
			// Match found - delete this token (single-use)
			deleteQuery := `DELETE FROM tokens WHERE id = $1`
			if _, err := p.ExecContext(ctx, deleteQuery, tokenID); err != nil {
				return false, fmt.Errorf("failed to delete used backup code: %w", err)
			}
			return true, nil
		}
	}

	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("error iterating backup codes: %w", err)
	}

	// No match found
	return false, nil
}

// EnableTwoFactor enables TOTP 2FA for a user
func (p *PostgreSQL) EnableTwoFactor(ctx context.Context, userID int, encryptedSecret string) error {
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
