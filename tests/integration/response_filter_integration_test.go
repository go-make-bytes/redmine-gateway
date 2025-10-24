package integration

import (
	"encoding/json"
	"testing"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/redmine"
)

// TestResponseFilteringLogic tests the core filtering logic with various response types
func TestResponseFilteringLogic(t *testing.T) {
	// Create test config with filtering enabled
	cfg := &config.Config{
		ResponseFilter: config.ResponseFilterConfig{
			Enabled:         true,
			SensitiveFields: []string{"api_key", "passwd_changed_on", "twofa_scheme"},
			PrivacyFields:   []string{"last_login_on"},
		},
	}

	// Create handler
	db := &database.PostgreSQL{}
	log := logger.New("info", "json")
	rh := redmine.NewRedmineHandler(cfg, db, log)

	t.Run("filter user current response", func(t *testing.T) {
		// Mock Redmine response for /users/current
		originalResponse := map[string]interface{}{
			"user": map[string]interface{}{
				"id":                1,
				"login":             "testuser",
				"firstname":         "Test",
				"lastname":          "User",
				"api_key":           "mock_api_key_12345",   // Should be filtered
				"passwd_changed_on": "2025-01-01T00:00:00Z", // Should be filtered
				"twofa_scheme":      "totp",                 // Should be filtered
				"last_login_on":     "2025-01-15T00:00:00Z", // Should be filtered
				"mail":              "test@example.com",     // Should be kept
				"admin":             false,                  // Should be kept
			},
		}

		originalJSON, _ := json.Marshal(originalResponse)
		filteredJSON, err := rh.SanitizeUserResponse(originalJSON)
		if err != nil {
			t.Fatalf("SanitizeUserResponse failed: %v", err)
		}

		var filteredResponse map[string]interface{}
		if err := json.Unmarshal(filteredJSON, &filteredResponse); err != nil {
			t.Fatalf("Failed to parse filtered response: %v", err)
		}

		user, ok := filteredResponse["user"].(map[string]interface{})
		if !ok {
			t.Fatal("Filtered response does not contain user object")
		}

		// Verify sensitive fields are removed
		sensitiveFields := []string{"api_key", "passwd_changed_on", "twofa_scheme", "last_login_on"}
		for _, field := range sensitiveFields {
			if _, exists := user[field]; exists {
				t.Errorf("Sensitive field '%s' was not filtered out", field)
			}
		}

		// Verify safe fields are preserved
		if user["login"] != "testuser" {
			t.Errorf("Expected login 'testuser', got %v", user["login"])
		}
		if user["mail"] != "test@example.com" {
			t.Errorf("Expected mail 'test@example.com', got %v", user["mail"])
		}
		if user["admin"] != false {
			t.Errorf("Expected admin false, got %v", user["admin"])
		}
	})

	t.Run("filter user by ID response", func(t *testing.T) {
		// Mock Redmine response for /users/123
		originalResponse := map[string]interface{}{
			"user": map[string]interface{}{
				"id":                123,
				"login":             "otheruser",
				"firstname":         "Other",
				"lastname":          "User",
				"api_key":           "other_api_key_67890",  // Should be filtered
				"passwd_changed_on": "2025-02-01T00:00:00Z", // Should be filtered
				"mail":              "other@example.com",    // Should be kept
				"admin":             true,                   // Should be kept
			},
		}

		originalJSON, _ := json.Marshal(originalResponse)
		filteredJSON, err := rh.SanitizeUserResponse(originalJSON)
		if err != nil {
			t.Fatalf("SanitizeUserResponse failed: %v", err)
		}

		var filteredResponse map[string]interface{}
		json.Unmarshal(filteredJSON, &filteredResponse)

		user := filteredResponse["user"].(map[string]interface{})

		// Verify sensitive fields are removed
		if _, exists := user["api_key"]; exists {
			t.Error("api_key should be filtered")
		}
		if _, exists := user["passwd_changed_on"]; exists {
			t.Error("passwd_changed_on should be filtered")
		}

		// Verify safe fields are preserved
		if user["login"] != "otheruser" {
			t.Error("login should be preserved")
		}
		if user["admin"] != true {
			t.Error("admin should be preserved")
		}
	})

	t.Run("filter nested user objects", func(t *testing.T) {
		// Mock complex response with nested user objects (e.g., issue with author/assignee)
		originalResponse := map[string]interface{}{
			"issue": map[string]interface{}{
				"id":          456,
				"subject":     "Test Issue",
				"description": "Issue description",
				"author": map[string]interface{}{
					"id":      1,
					"login":   "author",
					"api_key": "author_key", // Should be filtered
					"mail":    "author@example.com",
				},
				"assigned_to": map[string]interface{}{
					"id":      2,
					"login":   "assignee",
					"api_key": "assignee_key", // Should be filtered
					"mail":    "assignee@example.com",
				},
				"status": map[string]interface{}{
					"id":   1,
					"name": "New",
				},
			},
		}

		originalJSON, _ := json.Marshal(originalResponse)
		filteredJSON, err := rh.SanitizeUserResponse(originalJSON)
		if err != nil {
			t.Fatalf("SanitizeUserResponse failed: %v", err)
		}

		var filteredResponse map[string]interface{}
		json.Unmarshal(filteredJSON, &filteredResponse)

		issue := filteredResponse["issue"].(map[string]interface{})
		author := issue["author"].(map[string]interface{})
		assignedTo := issue["assigned_to"].(map[string]interface{})

		// Verify API keys are removed from nested user objects
		if _, exists := author["api_key"]; exists {
			t.Error("api_key should be filtered from nested author")
		}
		if _, exists := assignedTo["api_key"]; exists {
			t.Error("api_key should be filtered from nested assigned_to")
		}

		// Verify other fields are preserved
		if author["login"] != "author" {
			t.Error("author login should be preserved")
		}
		if assignedTo["mail"] != "assignee@example.com" {
			t.Error("assignee mail should be preserved")
		}
		if issue["subject"] != "Test Issue" {
			t.Error("issue subject should be preserved")
		}
	})

	t.Run("no filtering when disabled", func(t *testing.T) {
		// Create config with filtering disabled
		disabledCfg := &config.Config{
			ResponseFilter: config.ResponseFilterConfig{
				Enabled: false,
			},
		}

		disabledRh := redmine.NewRedmineHandler(disabledCfg, db, log)

		originalJSON := `{"user":{"id":1,"api_key":"secret"}}`
		filteredJSON, err := disabledRh.SanitizeUserResponse([]byte(originalJSON))
		if err != nil {
			t.Fatalf("SanitizeUserResponse failed: %v", err)
		}

		// When disabled, response should be unchanged
		if string(filteredJSON) != originalJSON {
			t.Errorf("Response was modified when filtering disabled: got %s, want %s", string(filteredJSON), originalJSON)
		}
	})

	t.Run("endpoint detection", func(t *testing.T) {
		endpointTests := []struct {
			path     string
			expected bool
			desc     string
		}{
			{"/api/users/current", true, "current user endpoint"},
			{"/api/users/123", true, "user by ID endpoint"},
			{"/api/users/123.json", true, "user by ID with json"},
			{"/api/users", false, "user list endpoint"},
			{"/api/projects", false, "projects endpoint"},
			{"/api/issues", false, "issues endpoint"},
		}

		for _, tt := range endpointTests {
			t.Run(tt.desc, func(t *testing.T) {
				result := rh.IsUserEndpoint(tt.path)
				if result != tt.expected {
					t.Errorf("IsUserEndpoint(%s) = %v, want %v", tt.path, result, tt.expected)
				}
			})
		}
	})
}
