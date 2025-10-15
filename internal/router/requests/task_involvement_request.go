package requests

import (
	"errors"
	"fmt"
	"time"
)

// TaskInvolvementRequest represents the query parameters for task involvement report
type TaskInvolvementRequest struct {
	// FromDate - Start of date range (inclusive). ISO 8601 format: YYYY-MM-DD
	// If not provided, defaults to Monday of current week
	FromDate string `form:"from_date" binding:"omitempty,datetime=2006-01-02"`

	// ToDate - End of date range (inclusive). ISO 8601 format: YYYY-MM-DD
	// If not provided, defaults to Sunday of current week
	ToDate string `form:"to_date" binding:"omitempty,datetime=2006-01-02"`

	// SortBy - Field to sort results by
	// Valid values: "task_id", "spent_time", "subject"
	// Default: "task_id"
	SortBy string `form:"sort_by" binding:"omitempty,oneof=task_id spent_time subject"`

	// SortOrder - Sort direction
	// Valid values: "asc", "desc"
	// Default: "asc"
	SortOrder string `form:"sort_order" binding:"omitempty,oneof=asc desc"`

	// Limit - Maximum number of results to return
	// Default: 1000, Max: 1000
	Limit int `form:"limit" binding:"omitempty,min=1,max=1000"`

	// Offset - Number of results to skip
	// Default: 0
	Offset int `form:"offset" binding:"omitempty,min=0"`
}

// Validate performs additional validation beyond struct tags
func (r *TaskInvolvementRequest) Validate() error {
	// If both dates provided, ensure from_date <= to_date
	if r.FromDate != "" && r.ToDate != "" {
		from, err := time.Parse("2006-01-02", r.FromDate)
		if err != nil {
			return fmt.Errorf("invalid from_date format: %w", err)
		}
		to, err := time.Parse("2006-01-02", r.ToDate)
		if err != nil {
			return fmt.Errorf("invalid to_date format: %w", err)
		}
		if from.After(to) {
			return errors.New("from_date must be before or equal to to_date")
		}
	}

	// Ensure dates are not in the future
	now := time.Now()
	if r.ToDate != "" {
		to, err := time.Parse("2006-01-02", r.ToDate)
		if err != nil {
			return fmt.Errorf("invalid to_date format: %w", err)
		}
		if to.After(now) {
			return errors.New("to_date cannot be in the future")
		}
	}

	if r.FromDate != "" {
		from, err := time.Parse("2006-01-02", r.FromDate)
		if err != nil {
			return fmt.Errorf("invalid from_date format: %w", err)
		}
		if from.After(now) {
			return errors.New("from_date cannot be in the future")
		}
	}

	return nil
}

// ApplyDefaults sets default values for optional parameters
func (r *TaskInvolvementRequest) ApplyDefaults() {
	if r.SortBy == "" {
		r.SortBy = "task_id"
	}
	if r.SortOrder == "" {
		r.SortOrder = "asc"
	}
	if r.Limit == 0 {
		r.Limit = 1000
	}
}

// GetDateRange returns parsed start and end dates
// If no dates provided, returns current week (Monday-Sunday)
func (r *TaskInvolvementRequest) GetDateRange() (time.Time, time.Time, error) {
	if r.FromDate == "" && r.ToDate == "" {
		// Default to current week (ISO 8601: Monday = 1, Sunday = 7)
		now := time.Now()
		weekday := int(now.Weekday())
		if weekday == 0 {
			weekday = 7 // Convert Sunday from 0 to 7
		}
		monday := now.AddDate(0, 0, -(weekday - 1))
		sunday := monday.AddDate(0, 0, 6)

		// Start of Monday, end of Sunday
		from := time.Date(monday.Year(), monday.Month(), monday.Day(), 0, 0, 0, 0, monday.Location())
		to := time.Date(sunday.Year(), sunday.Month(), sunday.Day(), 23, 59, 59, 999999999, sunday.Location())

		return from, to, nil
	}

	// Parse from_date
	var from time.Time
	var err error
	if r.FromDate != "" {
		from, err = time.Parse("2006-01-02", r.FromDate)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid from_date format: %w", err)
		}
	} else {
		// If only to_date provided, default from_date to Monday of current week
		now := time.Now()
		weekday := int(now.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		monday := now.AddDate(0, 0, -(weekday - 1))
		from = monday
	}

	// Parse to_date
	var to time.Time
	if r.ToDate != "" {
		to, err = time.Parse("2006-01-02", r.ToDate)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid to_date format: %w", err)
		}
	} else {
		// If only from_date provided, default to_date to today
		to = time.Now()
	}

	// Set time boundaries
	from = time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, from.Location())
	to = time.Date(to.Year(), to.Month(), to.Day(), 23, 59, 59, 999999999, to.Location())

	return from, to, nil
}
