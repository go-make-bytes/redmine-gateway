package responses

import "time"

// TaskInvolvementResponse is the complete response structure
type TaskInvolvementResponse struct {
	Data     []TaskInvolvementItem `json:"data"`
	Metadata ResponseMetadata      `json:"metadata"`
}

// TaskInvolvementItem represents a single task with involvement details
type TaskInvolvementItem struct {
	TaskID        int     `json:"task_id"`
	Subject       string  `json:"subject"`
	SpentTime     float64 `json:"spent_time"`
	HaveMyComment int     `json:"have_my_comment"`
	StatusChanged int     `json:"status_changed"`
	StillAssignee int     `json:"still_assignee"`
}

// ResponseMetadata contains response metadata
type ResponseMetadata struct {
	TotalCount  int       `json:"total_count"`
	FromDate    string    `json:"from_date"`
	ToDate      string    `json:"to_date"`
	GeneratedAt time.Time `json:"generated_at"`
	// pagination
	HasNext *bool `json:"has_next,omitempty"`
	HasPrev *bool `json:"has_prev,omitempty"`
	Limit   *int  `json:"limit,omitempty"`
	Offset  *int  `json:"offset,omitempty"`
}
