package responses

// AuthResponse represents authentication response with session information
type AuthResponse struct {
	Authenticated bool   `json:"authenticated"`
	SessionToken  string `json:"session_token,omitempty"`
	UserID        int    `json:"user_id,omitempty"`
	AuthSourceID  *int   `json:"auth_source_id,omitempty"` // LDAP source ID if authenticated via LDAP
	ExpiresIn     int    `json:"expires_in"`
	CSRFToken     string `json:"csrf_token,omitempty"`
}

// SessionCheckResponse represents session validation response
type SessionCheckResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        int    `json:"user_id,omitempty"`
	Username      string `json:"username,omitempty"`
	ExpiresIn     int    `json:"expires_in,omitempty"`
	Error         string `json:"error,omitempty"`
}

// LogoutResponse represents logout confirmation
type LogoutResponse struct {
	Message string `json:"message"`
}

// TokenResponse represents OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// PasswordChangeRequiredResponse represents response when password change is required
type PasswordChangeRequiredResponse struct {
	RequiresPasswordChange bool   `json:"requires_password_change"`
	UserID                 int    `json:"user_id"`
	ReturnTo               string `json:"return_to,omitempty"`
	Message                string `json:"message"`
}

// PasswordChangeResponse represents password change operation response
type PasswordChangeResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// UserInfoResponse represents OAuth userinfo endpoint response
type UserInfoResponse struct {
	Sub       string `json:"sub"`       // User ID
	Login     string `json:"login"`     // Username
	FirstName string `json:"firstname"` // First name
	LastName  string `json:"lastname"`  // Last name
	Email     string `json:"email"`     // Email address
	Admin     bool   `json:"admin"`     // Admin status
}
