package responses

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error            string                 `json:"error"`
	ErrorDescription string                 `json:"error_description,omitempty"`
	ErrorCode        string                 `json:"error_code,omitempty"`
	Details          map[string]interface{} `json:"details,omitempty"` // Additional error details
}

// NewErrorResponse creates a new error response
func NewErrorResponse(error, description string) *ErrorResponse {
	return &ErrorResponse{
		Error:            error,
		ErrorDescription: description,
	}
}

// WithErrorCode adds an error code to the error response
func (e *ErrorResponse) WithErrorCode(code string) *ErrorResponse {
	e.ErrorCode = code
	return e
}
