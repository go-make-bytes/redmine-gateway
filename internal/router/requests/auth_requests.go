package requests

// AuthRequest represents secure authentication request
type AuthRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// AuthorizeRequest represents OAuth authorization request parameters
type AuthorizeRequest struct {
	ResponseType    string `form:"response_type" binding:"required"`
	ClientID        string `form:"client_id" binding:"required"`
	RedirectURI     string `form:"redirect_uri" binding:"required"`
	Scope           string `form:"scope"`
	State           string `form:"state"`
	CodeChallenge   string `form:"code_challenge"`
	ChallengeMethod string `form:"code_challenge_method"`
}

// ChangePasswordRequest represents password change request
type ChangePasswordRequest struct {
	UserID          int    `json:"user_id,omitempty"` // Optional: for users without session
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

// TokenRequest represents OAuth token exchange request
type TokenRequest struct {
	GrantType    string  `form:"grant_type" binding:"required"`
	Code         string  `form:"code"`
	RedirectURI  string  `form:"redirect_uri"`
	ClientID     string  `form:"client_id" binding:"required"`
	ClientSecret *string `form:"client_secret"` // Optional pointer for public clients
	RefreshToken string  `form:"refresh_token"`
	CodeVerifier string  `form:"code_verifier"` // PKCE verifier
}
