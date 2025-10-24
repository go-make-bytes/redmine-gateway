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
