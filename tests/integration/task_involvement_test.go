package integration

// Integration Tests for Task Involvement Endpoint
//
// These tests require a PostgreSQL database with Redmine schema.
// The tests will be skipped if no database is available.
//
// To run these tests:
//
// 1. Set up a test PostgreSQL database with Redmine schema
//    Example using Docker:
//    docker run -d --name redmine-test-db -e POSTGRES_DB=redmine_test -e POSTGRES_USER=redmine -e POSTGRES_PASSWORD=redmine -p 5432:5432 postgres:13
//
// 2. Create the Redmine database schema (you can use a Redmine installation or migration scripts)
//
// 3. Set the TEST_DATABASE_URL environment variable (optional, defaults to localhost):
//    export TEST_DATABASE_URL="postgres://postgres:test@localhost:5432/redmine?sslmode=disable"
//
// 4. Run the tests:
//    go test ./tests/integration/ -v
//
// To skip integration tests entirely:
//    export SKIP_INTEGRATION_TESTS=true
//    go test ./tests/integration/ -v
//
// Note: These tests create and modify data in the database. Use a dedicated test database.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/redmine"
	"github.com/go-make-bytes/redmine-gateway/internal/router/requests"
	"github.com/go-make-bytes/redmine-gateway/internal/router/responses"
)

// Test setup
var testDB *database.PostgreSQL
var testLogger *logger.Logger
var testHandler *redmine.RedmineHandler

func TestMain(m *testing.M) {
	// Skip integration tests if explicitly disabled
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		fmt.Println("Skipping integration tests: SKIP_INTEGRATION_TESTS=true")
		os.Exit(0)
	}

	// Setup test database
	var err error
	testDB, err = setupTestDatabase()
	if err != nil {
		// Skip integration tests if database is not available
		fmt.Printf("Skipping integration tests: %v\n", err)
		fmt.Println("To run integration tests, ensure a test PostgreSQL database is running.")
		fmt.Println("Set TEST_DATABASE_URL environment variable or use default: postgres://postgres:test@localhost:5432/redmine?sslmode=disable")
		fmt.Println("Or set SKIP_INTEGRATION_TESTS=true to skip these tests entirely.")
		os.Exit(0)
	}

	testLogger = logger.New("error", "json")
	testHandler = redmine.NewRedmineHandler(&config.Config{}, testDB, testLogger)

	// Run tests
	code := m.Run()

	// Cleanup
	if testDB != nil {
		testDB.Close()
	}

	os.Exit(code)
}

func setupTestDatabase() (*database.PostgreSQL, error) {
	// Use test database connection string from environment or default
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://postgres:test@localhost:5432/redmine?sslmode=disable"
	}

	db, err := database.NewPostgreSQL(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to test database: %w", err)
	}

	return db, nil
}

// TestEndpoint_ReturnsUnauthorizedWithoutAuth tests that endpoint returns 401 without authentication
func TestEndpoint_ReturnsUnauthorizedWithoutAuth(t *testing.T) {
	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/reports/task-involvement", testHandler.GetTaskInvolvement)

	// Create request without auth
	req, _ := http.NewRequest("GET", "/api/reports/task-involvement", nil)
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// TestEndpoint_ReturnsEmptyArrayForNoActivity tests that endpoint returns 200 with empty array for user with no activity
func TestEndpoint_ReturnsEmptyArrayForNoActivity(t *testing.T) {
	// Create test user with no activity
	userID := createTestUser(t, "testuser_noactivity")

	// Setup router
	router := setupRouterWithAuth()

	// Create authenticated request
	req := createAuthenticatedRequest(userID)
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var resp responses.TaskInvolvementResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Assert empty array
	if len(resp.Data) != 0 {
		t.Errorf("Expected empty array, got %d items", len(resp.Data))
	}

	// Assert metadata
	if resp.Metadata.TotalCount != 0 {
		t.Errorf("Expected total_count 0, got %d", resp.Metadata.TotalCount)
	}
}

// TestEndpoint_ReturnsTasksWithTimeEntries tests that endpoint returns tasks with time entries
func TestEndpoint_ReturnsTasksWithTimeEntries(t *testing.T) {
	// Create test user
	userID := createTestUser(t, "testuser_timeentries")

	// Create test project
	projectID := createTestProject(t, "testproject_time")

	// Create test issue assigned to user
	issueID := createTestIssue(t, "Test issue with time", projectID, userID, userID)

	// Create time entry for this week
	now := time.Now()
	createTestTimeEntry(t, issueID, userID, 3.5, now)

	// Setup router
	router := setupRouterWithAuth()

	// Create authenticated request
	req := createAuthenticatedRequest(userID)
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var resp responses.TaskInvolvementResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Assert we have one task
	if len(resp.Data) != 1 {
		t.Errorf("Expected 1 task, got %d", len(resp.Data))
	}

	// Assert task details
	task := resp.Data[0]
	if task.TaskID != issueID {
		t.Errorf("Expected task_id %d, got %d", issueID, task.TaskID)
	}
	if task.Subject != "Test issue with time" {
		t.Errorf("Expected subject 'Test issue with time', got '%s'", task.Subject)
	}
	if task.SpentTime != 3.5 {
		t.Errorf("Expected spent_time 3.5, got %f", task.SpentTime)
	}
	if task.StillAssignee != 1 {
		t.Errorf("Expected still_assignee 1, got %d", task.StillAssignee)
	}
}

// TestEndpoint_IncludesTasksWithComments tests that endpoint includes tasks with comments
func TestEndpoint_IncludesTasksWithComments(t *testing.T) {
	// Create test user
	userID := createTestUser(t, "testuser_comments")

	// Create test project
	projectID := createTestProject(t, "testproject_comments")

	// Create test issue assigned to user
	issueID := createTestIssue(t, "Test issue with comment", projectID, userID, userID)

	// Create comment for this week
	now := time.Now()
	createTestComment(t, issueID, userID, "This is a test comment", now)

	// Setup router
	router := setupRouterWithAuth()

	// Create authenticated request
	req := createAuthenticatedRequest(userID)
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var resp responses.TaskInvolvementResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Assert we have one task
	if len(resp.Data) != 1 {
		t.Errorf("Expected 1 task, got %d", len(resp.Data))
	}

	// Assert task details
	task := resp.Data[0]
	if task.TaskID != issueID {
		t.Errorf("Expected task_id %d, got %d", issueID, task.TaskID)
	}
	if task.HaveMyComment != 1 {
		t.Errorf("Expected have_my_comment 1, got %d", task.HaveMyComment)
	}
	if task.StillAssignee != 1 {
		t.Errorf("Expected still_assignee 1, got %d", task.StillAssignee)
	}
}

// TestEndpoint_IncludesTasksWithStatusChanges tests that endpoint includes tasks with status changes
func TestEndpoint_IncludesTasksWithStatusChanges(t *testing.T) {
	// Create test user
	userID := createTestUser(t, "testuser_status")

	// Create test project
	projectID := createTestProject(t, "testproject_status")

	// Create test issue assigned to user
	issueID := createTestIssue(t, "Test issue with status change", projectID, userID, userID)

	// Create status change for this week (status 1 -> 2)
	now := time.Now()
	createTestStatusChange(t, issueID, userID, 1, 2, now)

	// Setup router
	router := setupRouterWithAuth()

	// Create authenticated request
	req := createAuthenticatedRequest(userID)
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var resp responses.TaskInvolvementResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Assert we have one task
	if len(resp.Data) != 1 {
		t.Errorf("Expected 1 task, got %d", len(resp.Data))
	}

	// Assert task details
	task := resp.Data[0]
	if task.TaskID != issueID {
		t.Errorf("Expected task_id %d, got %d", issueID, task.TaskID)
	}
	if task.StatusChanged != 1 {
		t.Errorf("Expected status_changed 1, got %d", task.StatusChanged)
	}
	if task.StillAssignee != 1 {
		t.Errorf("Expected still_assignee 1, got %d", task.StillAssignee)
	}
}

// TestEndpoint_FiltersByCustomDateRange tests that endpoint filters by custom date range
func TestEndpoint_FiltersByCustomDateRange(t *testing.T) {
	// Create test user
	userID := createTestUser(t, "testuser_daterange")

	// Create test project
	projectID := createTestProject(t, "testproject_daterange")

	// Create two issues
	issue1ID := createTestIssue(t, "Issue in range", projectID, userID, userID)
	issue2ID := createTestIssue(t, "Issue out of range", projectID, userID, userID)

	// Create time entries: one in range, one out of range
	now := time.Now()
	lastWeek := now.AddDate(0, 0, -7)
	createTestTimeEntry(t, issue1ID, userID, 2.0, now)      // This week
	createTestTimeEntry(t, issue2ID, userID, 1.0, lastWeek) // Last week

	// Setup router
	router := setupRouterWithAuth()

	// Create authenticated request with date range (this week only)
	req, _ := http.NewRequest("GET", "/api/reports/task-involvement?from_date="+now.Format("2006-01-02")+"&to_date="+now.Format("2006-01-02"), nil)
	req.Header.Set("X-Test-User-ID", strconv.Itoa(userID))
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var resp responses.TaskInvolvementResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Assert we have only one task (the one in range)
	if len(resp.Data) != 1 {
		t.Errorf("Expected 1 task, got %d", len(resp.Data))
	}

	// Assert it's the correct task
	if len(resp.Data) > 0 {
		task := resp.Data[0]
		if task.TaskID != issue1ID {
			t.Errorf("Expected task_id %d, got %d", issue1ID, task.TaskID)
		}
		if task.SpentTime != 2.0 {
			t.Errorf("Expected spent_time 2.0, got %f", task.SpentTime)
		}
	}

	if resp.Metadata.FromDate != now.Format("2006-01-02") {
		t.Errorf("Expected metadata.from_date %s, got %s", now.Format("2006-01-02"), resp.Metadata.FromDate)
	}
	if resp.Metadata.ToDate != now.Format("2006-01-02") {
		t.Errorf("Expected metadata.to_date %s, got %s", now.Format("2006-01-02"), resp.Metadata.ToDate)
	}
}

// TestEndpoint_Returns400ForInvalidDateFormat tests that endpoint returns 400 for invalid date format
func TestEndpoint_Returns400ForInvalidDateFormat(t *testing.T) {
	// Setup router
	router := setupRouterWithAuth()

	// Create request with invalid date format
	req, _ := http.NewRequest("GET", "/api/reports/task-involvement?from_date=invalid-date", nil)
	req.Header.Set("X-Test-User-ID", strconv.Itoa(createTestUser(t, "testuser_invaliddate")))
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp responses.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if errResp.Error != "Invalid query parameters" {
		t.Errorf("Expected error 'Invalid query parameters', got '%s'", errResp.Error)
	}
	if errResp.ErrorDescription == "" {
		t.Error("Expected error_description to be populated")
	}
}

// TestEndpoint_Returns400ForInvalidDateOrder tests that endpoint returns 400 for from_date > to_date
func TestEndpoint_Returns400ForInvalidDateOrder(t *testing.T) {
	// Setup router
	router := setupRouterWithAuth()

	// Create request with invalid date order
	req, _ := http.NewRequest("GET", "/api/reports/task-involvement?from_date=2025-10-20&to_date=2025-10-15", nil)
	req.Header.Set("X-Test-User-ID", strconv.Itoa(createTestUser(t, "testuser_invalidorder")))
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp responses.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if errResp.ErrorCode != requests.ErrCodeInvalidDateRange {
		t.Errorf("Expected error_code %s, got %s", requests.ErrCodeInvalidDateRange, errResp.ErrorCode)
	}
	if errResp.Error != "Invalid date range" {
		t.Errorf("Expected error 'Invalid date range', got '%s'", errResp.Error)
	}
	if errResp.ErrorDescription == "" {
		t.Error("Expected error_description to be populated")
	}
}

// TestEndpoint_SortsByTaskIDAscending tests that endpoint sorts by task_id ascending
func TestEndpoint_SortsByTaskIDAscending(t *testing.T) {
	// Create test user
	userID := createTestUser(t, "testuser_sort_id")

	// Create test project
	projectID := createTestProject(t, "testproject_sort")

	// Create multiple issues with different IDs (in order to get sequential IDs)
	issue1ID := createTestIssue(t, "Task 1", projectID, userID, userID)
	issue2ID := createTestIssue(t, "Task 2", projectID, userID, userID)
	issue3ID := createTestIssue(t, "Task 3", projectID, userID, userID)

	// Add time entries for all issues
	now := time.Now()
	createTestTimeEntry(t, issue3ID, userID, 1.0, now)
	createTestTimeEntry(t, issue1ID, userID, 2.0, now)
	createTestTimeEntry(t, issue2ID, userID, 3.0, now)

	// Setup router
	router := setupRouterWithAuth()

	// Create authenticated request with sort_by=task_id&sort_order=asc
	req, _ := http.NewRequest("GET", "/api/reports/task-involvement?sort_by=task_id&sort_order=asc", nil)
	req.Header.Set("X-Test-User-ID", strconv.Itoa(userID))
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var resp responses.TaskInvolvementResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Assert we have three tasks
	if len(resp.Data) != 3 {
		t.Errorf("Expected 3 tasks, got %d", len(resp.Data))
	}

	// Assert sorted by task_id ascending
	if len(resp.Data) == 3 {
		if resp.Data[0].TaskID != issue1ID {
			t.Errorf("First task should be %d, got %d", issue1ID, resp.Data[0].TaskID)
		}
		if resp.Data[1].TaskID != issue2ID {
			t.Errorf("Second task should be %d, got %d", issue2ID, resp.Data[1].TaskID)
		}
		if resp.Data[2].TaskID != issue3ID {
			t.Errorf("Third task should be %d, got %d", issue3ID, resp.Data[2].TaskID)
		}
	}
}

// TestEndpoint_SortsBySpentTimeDescending tests that endpoint sorts by spent_time descending
func TestEndpoint_SortsBySpentTimeDescending(t *testing.T) {
	// Create test user
	userID := createTestUser(t, "testuser_sort_time")

	// Create test project
	projectID := createTestProject(t, "testproject_sort_time")

	// Create multiple issues with different time spent
	issue1ID := createTestIssue(t, "Low time task", projectID, userID, userID)
	issue2ID := createTestIssue(t, "High time task", projectID, userID, userID)
	issue3ID := createTestIssue(t, "Mid time task", projectID, userID, userID)

	// Add time entries with different hours
	now := time.Now()
	createTestTimeEntry(t, issue1ID, userID, 1.5, now)
	createTestTimeEntry(t, issue2ID, userID, 5.0, now)
	createTestTimeEntry(t, issue3ID, userID, 3.0, now)

	// Setup router
	router := setupRouterWithAuth()

	// Create authenticated request with sort_by=spent_time&sort_order=desc
	req, _ := http.NewRequest("GET", "/api/reports/task-involvement?sort_by=spent_time&sort_order=desc", nil)
	req.Header.Set("X-Test-User-ID", strconv.Itoa(userID))
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var resp responses.TaskInvolvementResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Assert we have three tasks
	if len(resp.Data) != 3 {
		t.Errorf("Expected 3 tasks, got %d", len(resp.Data))
	}

	// Assert sorted by spent_time descending
	if len(resp.Data) == 3 {
		if resp.Data[0].SpentTime != 5.0 {
			t.Errorf("First task spent_time should be 5.0, got %f", resp.Data[0].SpentTime)
		}
		if resp.Data[1].SpentTime != 3.0 {
			t.Errorf("Second task spent_time should be 3.0, got %f", resp.Data[1].SpentTime)
		}
		if resp.Data[2].SpentTime != 1.5 {
			t.Errorf("Third task spent_time should be 1.5, got %f", resp.Data[2].SpentTime)
		}
	}
}

// TestEndpoint_PaginatesWithLimit tests that endpoint paginates with limit=20
func TestEndpoint_PaginatesWithLimit(t *testing.T) {
	// Create test user
	userID := createTestUser(t, "testuser_pagination")

	// Create test project
	projectID := createTestProject(t, "testproject_pagination")

	// Create 25 issues
	now := time.Now()
	for i := 0; i < 25; i++ {
		issueID := createTestIssue(t, fmt.Sprintf("Task %d", i), projectID, userID, userID)
		createTestTimeEntry(t, issueID, userID, 1.0, now)
	}

	// Setup router
	router := setupRouterWithAuth()

	// Test first page with limit=20
	req1, _ := http.NewRequest("GET", "/api/reports/task-involvement?limit=20&offset=0", nil)
	req1.Header.Set("X-Test-User-ID", strconv.Itoa(userID))
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w1.Code)
	}

	var resp1 responses.TaskInvolvementResponse
	if err := json.Unmarshal(w1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(resp1.Data) != 20 {
		t.Errorf("Expected 20 tasks on first page, got %d", len(resp1.Data))
	}

	if resp1.Metadata.TotalCount != 25 {
		t.Errorf("Expected total_count 25, got %d", resp1.Metadata.TotalCount)
	}

	// Check has_next flag
	if resp1.Metadata.HasNext == nil || !*resp1.Metadata.HasNext {
		t.Error("Expected has_next to be true for first page")
	}

	// Test second page with limit=20&offset=20
	req2, _ := http.NewRequest("GET", "/api/reports/task-involvement?limit=20&offset=20", nil)
	req2.Header.Set("X-Test-User-ID", strconv.Itoa(userID))
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w2.Code)
	}

	var resp2 responses.TaskInvolvementResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(resp2.Data) != 5 {
		t.Errorf("Expected 5 tasks on second page, got %d", len(resp2.Data))
	}

	// Check has_prev flag
	if resp2.Metadata.HasPrev == nil || !*resp2.Metadata.HasPrev {
		t.Error("Expected has_prev to be true for second page")
	}
}

// TestEndpoint_Returns400ForInvalidSortField tests that endpoint returns 400 for invalid sort field
func TestEndpoint_Returns400ForInvalidSortField(t *testing.T) {
	// Setup router
	router := setupRouterWithAuth()

	// Create request with invalid sort_by
	req, _ := http.NewRequest("GET", "/api/reports/task-involvement?sort_by=invalid_field", nil)
	req.Header.Set("X-Test-User-ID", strconv.Itoa(createTestUser(t, "testuser_invalidsort")))
	w := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp responses.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if errResp.Error == "" {
		t.Error("Expected error message to be populated")
	}
}

// Helper functions for test data setup
func createTestUser(t *testing.T, login string) int {
	ctx := context.Background()
	query := `
		INSERT INTO users (login, firstname, lastname, status, created_on, updated_on)
		VALUES ($1, $1, $1, 1, NOW(), NOW())
		RETURNING id
	`
	var userID int
	err := testDB.QueryRowContext(ctx, query, login).Scan(&userID)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create email address entry
	email := login + "@test.com"
	_, err = testDB.ExecContext(ctx, `
		INSERT INTO email_addresses (user_id, address, is_default, notify, created_on, updated_on)
		VALUES ($1, $2, true, true, NOW(), NOW())
	`, userID, email)
	if err != nil {
		t.Fatalf("Failed to create test email address: %v", err)
	}

	return userID
}

func createTestProject(t *testing.T, name string) int {
	ctx := context.Background()

	// Generate unique identifier to avoid conflicts
	identifier := fmt.Sprintf("%s_%d", name, time.Now().UnixNano())

	query := `
		INSERT INTO projects (name, identifier, status, created_on, updated_on)
		VALUES ($1, $2, 1, NOW(), NOW())
		RETURNING id
	`
	var projectID int
	err := testDB.QueryRowContext(ctx, query, name, identifier).Scan(&projectID)
	if err != nil {
		t.Fatalf("Failed to create test project: %v", err)
	}
	return projectID
}

func createTestIssue(t *testing.T, subject string, projectID, authorID, assignedToID int) int {
	ctx := context.Background()
	query := `
		INSERT INTO issues (subject, project_id, tracker_id, author_id, assigned_to_id, status_id, priority_id, created_on, updated_on)
		VALUES ($1, $2, 1, $3, $4, 1, 1, NOW(), NOW())
		RETURNING id
	`
	var issueID int
	err := testDB.QueryRowContext(ctx, query, subject, projectID, authorID, assignedToID).Scan(&issueID)
	if err != nil {
		t.Fatalf("Failed to create test issue: %v", err)
	}
	return issueID
}

func createTestTimeEntry(t *testing.T, issueID, userID int, hours float64, spentOn time.Time) {
	ctx := context.Background()

	// Get project_id from the issue
	var projectID int
	err := testDB.QueryRowContext(ctx, "SELECT project_id FROM issues WHERE id = $1", issueID).Scan(&projectID)
	if err != nil {
		t.Fatalf("Failed to get project_id from issue: %v", err)
	}

	// Calculate tyear, tmonth, tweek
	year, month, _ := spentOn.Date()
	_, week := spentOn.ISOWeek()

	query := `
		INSERT INTO time_entries (project_id, user_id, issue_id, hours, activity_id, spent_on, tyear, tmonth, tweek, created_on, updated_on)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
	`
	_, err = testDB.ExecContext(ctx, query, projectID, userID, issueID, hours, 10, spentOn, year, int(month), week)
	if err != nil {
		t.Fatalf("Failed to create test time entry: %v", err)
	}
}

func createTestComment(t *testing.T, issueID, userID int, comment string, createdOn time.Time) {
	ctx := context.Background()
	query := `
		INSERT INTO journals (journalized_id, journalized_type, user_id, notes, created_on)
		VALUES ($1, 'Issue', $2, $3, $4)
	`
	_, err := testDB.ExecContext(ctx, query, issueID, userID, comment, createdOn)
	if err != nil {
		t.Fatalf("Failed to create test comment: %v", err)
	}
}

func createTestStatusChange(t *testing.T, issueID, userID int, oldStatus, newStatus int, createdOn time.Time) {
	ctx := context.Background()

	// First create the journal entry
	query := `
		INSERT INTO journals (journalized_id, journalized_type, user_id, created_on)
		VALUES ($1, 'Issue', $2, $3)
		RETURNING id
	`
	var journalID int
	err := testDB.QueryRowContext(ctx, query, issueID, userID, createdOn).Scan(&journalID)
	if err != nil {
		t.Fatalf("Failed to create test journal: %v", err)
	}

	// Then create the journal detail for status change
	detailQuery := `
		INSERT INTO journal_details (journal_id, property, prop_key, old_value, value)
		VALUES ($1, 'attr', 'status_id', $2, $3)
	`
	_, err = testDB.ExecContext(ctx, detailQuery, journalID, oldStatus, newStatus)
	if err != nil {
		t.Fatalf("Failed to create test journal detail: %v", err)
	}
}

func createAuthenticatedRequest(userID int) *http.Request {
	req, _ := http.NewRequest("GET", "/api/reports/task-involvement", nil)
	// Set user_id in context (this would normally be done by auth middleware)
	req.Header.Set("X-Test-User-ID", strconv.Itoa(userID))
	return req
}

func setupRouterWithAuth() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Mock auth middleware that sets user_id from header
	router.Use(func(c *gin.Context) {
		if userIDStr := c.GetHeader("X-Test-User-ID"); userIDStr != "" {
			if id, err := strconv.Atoi(userIDStr); err == nil {
				c.Set("user_id", id)
			}
		}
	})

	router.GET("/api/reports/task-involvement", testHandler.GetTaskInvolvement)
	return router
}
