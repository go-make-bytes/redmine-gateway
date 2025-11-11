package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
)

// Platform represents the type of Redmine platform
type Platform string

const (
	PlatformOSS  Platform = "oss"  // Open Source Redmine
	PlatformEasy Platform = "easy" // EasyRedmine
)

// PlatformInfo contains information about the detected platform
type PlatformInfo struct {
	Platform       Platform
	Version        string
	Has2FATable    bool
	HasUserTypes   bool
	HasEasyModules bool
}

// DetectPlatform checks database for EasyRedmine-specific tables
func (p *PostgreSQL) DetectPlatform(ctx context.Context, cfg *config.PlatformConfig) (*PlatformInfo, error) {
	info := &PlatformInfo{
		Platform: PlatformOSS, // default to OSS
	}

	// If force mode is set, use it
	if cfg.ForceMode != "" {
		switch cfg.ForceMode {
		case "easy":
			info.Platform = PlatformEasy
			return info, nil
		case "oss":
			info.Platform = PlatformOSS
			return info, nil
		default:
			return nil, fmt.Errorf("invalid force_mode: %s (must be 'oss' or 'easy')", cfg.ForceMode)
		}
	}

	// If auto-detect is disabled and no force mode, default to OSS
	if !cfg.AutoDetect {
		return info, nil
	}

	// Check for easy_twofa_user_schemes table
	query := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = 'easy_twofa_user_schemes'
		)
	`
	err := p.QueryRowContext(ctx, query).Scan(&info.Has2FATable)
	if err != nil {
		return nil, fmt.Errorf("failed to check for easy_twofa_user_schemes table: %w", err)
	}

	// Check for easy_user_types table
	query = `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = 'easy_user_types'
		)
	`
	err = p.QueryRowContext(ctx, query).Scan(&info.HasUserTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to check for easy_user_types table: %w", err)
	}

	// Check for easy_user_type_id column in users table
	query = `
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_schema = 'public' 
			AND table_name = 'users' 
			AND column_name = 'easy_user_type_id'
		)
	`
	var hasEasyUserTypeColumn bool
	err = p.QueryRowContext(ctx, query).Scan(&hasEasyUserTypeColumn)
	if err != nil {
		return nil, fmt.Errorf("failed to check for easy_user_type_id column: %w", err)
	}

	// If we have Easy tables, it's EasyRedmine
	if info.Has2FATable || info.HasUserTypes || hasEasyUserTypeColumn {
		info.Platform = PlatformEasy
		info.HasEasyModules = true
	}

	// Try to detect version (optional, non-critical)
	info.Version, _ = p.detectVersion(ctx, info.Platform)

	return info, nil
}

// detectVersion attempts to detect the Redmine/EasyRedmine version
func (p *PostgreSQL) detectVersion(ctx context.Context, platform Platform) (string, error) {
	// Try to get version from settings table
	query := `SELECT value FROM settings WHERE name = $1 LIMIT 1`

	var version sql.NullString
	var versionKey string

	if platform == PlatformEasy {
		versionKey = "easy_version"
	} else {
		versionKey = "app_version"
	}

	err := p.QueryRowContext(ctx, query, versionKey).Scan(&version)
	if err == sql.ErrNoRows || !version.Valid {
		// Version not found, return empty string
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to query version: %w", err)
	}

	return version.String, nil
}

// GetPlatformInfo returns the cached platform information
func (p *PostgreSQL) GetPlatformInfo() *PlatformInfo {
	if p.platformInfo == nil {
		// Return default OSS if not initialized
		return &PlatformInfo{
			Platform: PlatformOSS,
		}
	}
	return p.platformInfo
}

// SetPlatformInfo sets the platform information (called during initialization)
func (p *PostgreSQL) SetPlatformInfo(info *PlatformInfo) {
	p.platformInfo = info
}
