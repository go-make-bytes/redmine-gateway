package responses

// TwoFASetupResponse represents response when initiating 2FA setup
type TwoFASetupResponse struct {
	Secret    string `json:"secret"`      // Base32-encoded TOTP secret (for manual entry)
	QRCodeURL string `json:"qr_code_url"` // Base64-encoded PNG data URL
	Issuer    string `json:"issuer"`      // Issuer name (displayed in app)
	Account   string `json:"account"`     // Account name (username)
}

// TwoFAConfirmResponse represents response after confirming 2FA setup
type TwoFAConfirmResponse struct {
	Success     bool     `json:"success"`
	BackupCodes []string `json:"backup_codes"` // Display once to user
	Message     string   `json:"message"`
}

// TwoFAVerifyResponse represents response after verifying 2FA code
type TwoFAVerifyResponse struct {
	Success      bool   `json:"success"`
	AccessToken  string `json:"access_token,omitempty"`  // JWT access token (if successful)
	RefreshToken string `json:"refresh_token,omitempty"` // JWT refresh token (if successful)
	Message      string `json:"message"`
}

// TwoFAChallengeResponse represents response when 2FA verification is required
type TwoFAChallengeResponse struct {
	RequiresTwoFA  bool   `json:"requires_two_fa"`
	SessionToken   string `json:"session_token"`   // Temporary 2FA session token
	EnrollmentMode bool   `json:"enrollment_mode"` // True if user needs to enroll
	Message        string `json:"message"`
	TimeoutSeconds int    `json:"timeout_seconds"` // Session timeout duration
	MaxAttempts    int    `json:"max_attempts"`    // Maximum verification attempts allowed
}

// BackupCodesResponse represents response when generating backup codes
type BackupCodesResponse struct {
	Codes   []string `json:"codes"`
	Count   int      `json:"count"`
	Message string   `json:"message"`
}

// TwoFAStatusResponse represents current 2FA status for a user
type TwoFAStatusResponse struct {
	Enabled         bool   `json:"enabled"`
	Scheme          string `json:"scheme,omitempty"` // "totp" or empty
	BackupCodesLeft int    `json:"backup_codes_left"`
	LastUsed        *int64 `json:"last_used,omitempty"` // Unix timestamp
	Required        bool   `json:"required"`            // Whether 2FA is required for this user
}
