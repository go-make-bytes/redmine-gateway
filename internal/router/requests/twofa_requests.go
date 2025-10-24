package requests

// TwoFASetupRequest represents request to initiate 2FA setup
type TwoFASetupRequest struct {
	// No fields needed - uses authenticated session
}

// TwoFAConfirmRequest represents request to confirm 2FA setup
type TwoFAConfirmRequest struct {
	Code   string `json:"code" binding:"required,len=6,numeric"` // TOTP verification code
	Secret string `json:"secret" binding:"required"`             // TOTP secret from setup response
}

// TwoFAVerifyRequest represents request to verify 2FA code during login
type TwoFAVerifyRequest struct {
	SessionToken string `json:"session_token" binding:"required"`     // 2FA session token
	Code         string `json:"code" binding:"required,min=6,max=12"` // TOTP code (6 digits) or backup code (12 chars)
	IsBackupCode bool   `json:"is_backup_code,omitempty"`             // True if using backup code
}

// TwoFADisableRequest represents request to disable 2FA
type TwoFADisableRequest struct {
	Password string `json:"password" binding:"required"`           // User password for verification
	Code     string `json:"code" binding:"required,len=6,numeric"` // Current TOTP code
}

// TwoFABackupCodesRequest represents request to regenerate backup codes
type TwoFABackupCodesRequest struct {
	Code string `json:"code" binding:"required,len=6,numeric"` // Current TOTP code for confirmation
}
