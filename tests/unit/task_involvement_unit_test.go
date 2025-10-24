package unit

import (
	"testing"
	"time"

	"github.com/go-make-bytes/redmine-gateway/internal/router/requests"
)

// TestGetDateRange_CurrentWeek tests that GetDateRange returns current Monday-Sunday when no params provided
func TestGetDateRange_CurrentWeek(t *testing.T) {
	// Unit test: GetDateRange returns current Monday-Sunday when no params
	req := &requests.TaskInvolvementRequest{}

	from, to, err := req.GetDateRange()
	if err != nil {
		t.Fatalf("GetDateRange() error = %v, want nil", err)
	}

	// Verify it's a Monday
	if from.Weekday() != time.Monday {
		t.Errorf("from date weekday = %v, want Monday", from.Weekday())
	}

	// Verify it's a Sunday
	if to.Weekday() != time.Sunday {
		t.Errorf("to date weekday = %v, want Sunday", to.Weekday())
	}

	// Verify from is before to
	if !from.Before(to) {
		t.Errorf("from date %v should be before to date %v", from, to)
	}

	// Verify range spans at least 6 days and not more than 8 days to allow for DST shifts
	duration := to.Sub(from)
	if duration < 6*24*time.Hour {
		t.Errorf("date range duration = %v, want at least 6 days", duration)
	}
	if duration > 8*24*time.Hour {
		t.Errorf("date range duration = %v, want no more than 8 days", duration)
	}
}

// TestValidate_RejectsFutureDates tests that Validate rejects future dates
func TestValidate_RejectsFutureDates(t *testing.T) {
	// Unit test: Validate rejects future dates
	future := time.Now().AddDate(0, 0, 7).Format("2006-01-02")

	tests := []struct {
		name    string
		req     *requests.TaskInvolvementRequest
		wantErr bool
	}{
		{
			name: "future from_date",
			req: &requests.TaskInvolvementRequest{
				FromDate: future,
			},
			wantErr: true,
		},
		{
			name: "future to_date",
			req: &requests.TaskInvolvementRequest{
				ToDate: future,
			},
			wantErr: true,
		},
		{
			name: "both future dates",
			req: &requests.TaskInvolvementRequest{
				FromDate: future,
				ToDate:   future,
			},
			wantErr: true,
		},
		{
			name: "past dates are valid",
			req: &requests.TaskInvolvementRequest{
				FromDate: "2025-10-01",
				ToDate:   "2025-10-07",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidate_RejectsInvalidDateOrder tests that Validate rejects from_date > to_date
func TestValidate_RejectsInvalidDateOrder(t *testing.T) {
	// Unit test: Validate rejects from_date > to_date
	req := &requests.TaskInvolvementRequest{
		FromDate: "2025-10-15",
		ToDate:   "2025-10-08",
	}

	err := req.Validate()
	if err == nil {
		t.Error("Validate() expected error for from_date > to_date, got nil")
	}
}

// TestApplyDefaults_SetsCorrectValues tests that ApplyDefaults sets correct default values
func TestApplyDefaults_SetsCorrectValues(t *testing.T) {
	// Unit test: ApplyDefaults sets correct default values
	req := &requests.TaskInvolvementRequest{}

	req.ApplyDefaults()

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{
			name: "SortBy default",
			got:  req.SortBy,
			want: "task_id",
		},
		{
			name: "SortOrder default",
			got:  req.SortOrder,
			want: "asc",
		},
		{
			name: "Limit default",
			got:  req.Limit,
			want: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("ApplyDefaults() %s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestGetDateRange_ParsesCustomDates tests that GetDateRange parses from_date and to_date correctly
func TestGetDateRange_ParsesCustomDates(t *testing.T) {
	// Unit test: GetDateRange parses from_date and to_date correctly
	req := &requests.TaskInvolvementRequest{
		FromDate: "2025-10-01",
		ToDate:   "2025-10-07",
	}

	from, to, err := req.GetDateRange()
	if err != nil {
		t.Fatalf("GetDateRange() error = %v, want nil", err)
	}

	expectedFrom := time.Date(2025, 10, 1, 0, 0, 0, 0, from.Location())
	expectedTo := time.Date(2025, 10, 7, 23, 59, 59, 999999999, to.Location())

	if from.Year() != expectedFrom.Year() || from.Month() != expectedFrom.Month() || from.Day() != expectedFrom.Day() {
		t.Errorf("from date = %v, want %v", from, expectedFrom)
	}

	if to.Year() != expectedTo.Year() || to.Month() != expectedTo.Month() || to.Day() != expectedTo.Day() {
		t.Errorf("to date = %v, want %v", to, expectedTo)
	}
}

// TestGetDateRange_DefaultsToDateToToday tests that GetDateRange with only from_date defaults to_date to today
func TestGetDateRange_DefaultsToDateToToday(t *testing.T) {
	// Unit test: GetDateRange with only from_date defaults to_date to today
	req := &requests.TaskInvolvementRequest{
		FromDate: "2025-10-01",
	}

	from, to, err := req.GetDateRange()
	if err != nil {
		t.Fatalf("GetDateRange() error = %v, want nil", err)
	}

	now := time.Now()
	if to.Year() != now.Year() || to.Month() != now.Month() || to.Day() != now.Day() {
		t.Errorf("to date = %v, want today %v", to, now)
	}

	expectedFrom := time.Date(2025, 10, 1, 0, 0, 0, 0, from.Location())
	if from.Year() != expectedFrom.Year() || from.Month() != expectedFrom.Month() || from.Day() != expectedFrom.Day() {
		t.Errorf("from date = %v, want %v", from, expectedFrom)
	}
}

// TestValidate_InvalidISO8601Format tests that Validate returns error for invalid ISO 8601 format
func TestValidate_InvalidISO8601Format(t *testing.T) {
	// Unit test: Validate returns error for invalid ISO 8601 format
	tests := []struct {
		name    string
		req     *requests.TaskInvolvementRequest
		wantErr bool
	}{
		{
			name: "invalid from_date format",
			req: &requests.TaskInvolvementRequest{
				FromDate: "10/01/2025",
			},
			wantErr: true,
		},
		{
			name: "invalid to_date format",
			req: &requests.TaskInvolvementRequest{
				ToDate: "2025-13-01", // Invalid month
			},
			wantErr: true,
		},
		{
			name: "valid ISO 8601 format",
			req: &requests.TaskInvolvementRequest{
				FromDate: "2025-10-01",
				ToDate:   "2025-10-07",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestApplyDefaults_HandlesSort tests that ApplyDefaults handles sorting and pagination params
func TestApplyDefaults_HandlesSort(t *testing.T) {
	// Unit test: ApplyDefaults handles sorting and pagination params
	tests := []struct {
		name     string
		req      *requests.TaskInvolvementRequest
		expected *requests.TaskInvolvementRequest
	}{
		{
			name: "empty request gets all defaults",
			req:  &requests.TaskInvolvementRequest{},
			expected: &requests.TaskInvolvementRequest{
				SortBy:    "task_id",
				SortOrder: "asc",
				Limit:     1000,
			},
		},
		{
			name: "partial values preserved",
			req: &requests.TaskInvolvementRequest{
				SortBy: "spent_time",
				Limit:  50,
			},
			expected: &requests.TaskInvolvementRequest{
				SortBy:    "spent_time",
				SortOrder: "asc",
				Limit:     50,
			},
		},
		{
			name: "all values preserved",
			req: &requests.TaskInvolvementRequest{
				SortBy:    "subject",
				SortOrder: "desc",
				Limit:     100,
				Offset:    20,
			},
			expected: &requests.TaskInvolvementRequest{
				SortBy:    "subject",
				SortOrder: "desc",
				Limit:     100,
				Offset:    20,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.req.ApplyDefaults()

			if tt.req.SortBy != tt.expected.SortBy {
				t.Errorf("SortBy = %v, want %v", tt.req.SortBy, tt.expected.SortBy)
			}
			if tt.req.SortOrder != tt.expected.SortOrder {
				t.Errorf("SortOrder = %v, want %v", tt.req.SortOrder, tt.expected.SortOrder)
			}
			if tt.req.Limit != tt.expected.Limit {
				t.Errorf("Limit = %v, want %v", tt.req.Limit, tt.expected.Limit)
			}
			if tt.req.Offset != tt.expected.Offset {
				t.Errorf("Offset = %v, want %v", tt.req.Offset, tt.expected.Offset)
			}
		})
	}
}

// TestValidate_AcceptsValidSortBy tests that Validate accepts valid sort_by values
func TestValidate_AcceptsValidSortBy(t *testing.T) {
	// Unit test: Validate accepts valid sort_by values
	tests := []struct {
		name    string
		sortBy  string
		wantErr bool
	}{
		{
			name:    "task_id is valid",
			sortBy:  "task_id",
			wantErr: false,
		},
		{
			name:    "spent_time is valid",
			sortBy:  "spent_time",
			wantErr: false,
		},
		{
			name:    "subject is valid",
			sortBy:  "subject",
			wantErr: false,
		},
		{
			name:    "invalid_field rejected",
			sortBy:  "invalid_field",
			wantErr: true,
		},
		{
			name:    "empty string accepted (will default)",
			sortBy:  "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &requests.TaskInvolvementRequest{
				SortBy: tt.sortBy,
			}
			err := req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() with sort_by=%s error = %v, wantErr %v", tt.sortBy, err, tt.wantErr)
			}
		})
	}
}
