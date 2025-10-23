package responses

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error            string                 `json:"error"`
	ErrorDescription string                 `json:"error_description,omitempty"`
	ErrorCode        string                 `json:"error_code,omitempty"`
	ErrorURI         string                 `json:"error_uri,omitempty"`
	Details          map[string]interface{} `json:"details,omitempty"` // Additional error details
}

// OAuthErrorResponse represents OAuth 2.0 error response
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	State            string `json:"state,omitempty"`
}

// RedmineAPIErrorResponse represents Redmine API error details
type RedmineAPIErrorResponse struct {
	Error         string   `json:"error"`
	ErrorCode     string   `json:"error_code,omitempty"`
	Description   string   `json:"description,omitempty"`
	Help          string   `json:"help,omitempty"`
	AdminHelp     string   `json:"admin_help,omitempty"`
	Documentation string   `json:"documentation,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

// NewErrorResponse creates a new error response
func NewErrorResponse(error, description string) *ErrorResponse {
	return &ErrorResponse{
		Error:            error,
		ErrorDescription: description,
	}
}

// NewOAuthErrorResponse creates a new OAuth error response
func NewOAuthErrorResponse(error, description, state string) *OAuthErrorResponse {
	return &OAuthErrorResponse{
		Error:            error,
		ErrorDescription: description,
		State:            state,
	}
}

// WithErrorCode adds an error code to the error response
func (e *ErrorResponse) WithErrorCode(code string) *ErrorResponse {
	e.ErrorCode = code
	return e
}

// WithErrorURI adds an error URI to the error response
func (e *ErrorResponse) WithErrorURI(uri string) *ErrorResponse {
	e.ErrorURI = uri
	return e
}
