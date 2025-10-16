package responses

import "time"

// HealthResponse represents service health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version,omitempty"`
}

// RedmineStatusResponse represents Redmine connection status
type RedmineStatusResponse struct {
	Status       string    `json:"status"`
	RedmineURL   string    `json:"redmine_url,omitempty"`
	ResponseCode int       `json:"response_code,omitempty"`
	Timestamp    time.Time `json:"timestamp,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// DiagnosticResponse represents comprehensive diagnostic information
type DiagnosticResponse struct {
	Timestamp     time.Time              `json:"timestamp"`
	Service       string                 `json:"service"`
	RedmineURL    string                 `json:"redmine_url"`
	OverallStatus string                 `json:"overall_status"`
	Checks        map[string]interface{} `json:"checks"`
}

// DiagnosticCheck represents a single diagnostic check result
type DiagnosticCheck struct {
	Status     string      `json:"status"`
	Error      string      `json:"error,omitempty"`
	Note       string      `json:"note,omitempty"`
	Warning    string      `json:"warning,omitempty"`
	AdminNote  string      `json:"admin_note,omitempty"`
	Enabled    *bool       `json:"enabled,omitempty"`
	StatusCode int         `json:"status_code,omitempty"`
	Details    interface{} `json:"details,omitempty"`
}
