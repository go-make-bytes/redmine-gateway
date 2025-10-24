package unit

import (
	"encoding/json"
	"testing"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
	"github.com/go-make-bytes/redmine-gateway/internal/redmine"
)

func TestIsUserEndpoint(t *testing.T) {
	// Create a minimal config for testing
	cfg := &config.Config{
		ResponseFilter: config.ResponseFilterConfig{
			Enabled:         true,
			SensitiveFields: []string{"api_key", "passwd_changed_on", "twofa_scheme"},
			PrivacyFields:   []string{"last_login_on"},
		},
	}

	// Create handler (we'll mock the db and logger)
	db := &database.PostgreSQL{} // This will be nil but that's ok for this test
	log := &logger.Logger{}      // This will be nil but that's ok for this test
	rh := redmine.NewRedmineHandler(cfg, db, log)

	tests := []struct {
		path     string
		expected bool
		name     string
	}{
		{"/api/users/current", true, "current user endpoint"},
		{"/api/users/123", true, "user by ID endpoint"},
		{"/api/users/123.json", true, "user by ID with json suffix"},
		{"/api/users", false, "user list endpoint (safe)"},
		{"/api/projects", false, "projects endpoint"},
		{"/api/issues", false, "issues endpoint"},
		{"/api/time_entries", false, "time entries endpoint"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rh.IsUserEndpoint(tt.path)
			if result != tt.expected {
				t.Errorf("isUserEndpoint(%s) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestSanitizeUserResponse(t *testing.T) {
	// Create config with filtering enabled
	cfg := &config.Config{
		ResponseFilter: config.ResponseFilterConfig{
			Enabled:         true,
			SensitiveFields: []string{"api_key", "passwd_changed_on", "twofa_scheme"},
			PrivacyFields:   []string{"last_login_on"},
		},
	}

	db := &database.PostgreSQL{}
	log := &logger.Logger{}
	rh := redmine.NewRedmineHandler(cfg, db, log)

	// Test data with sensitive fields
	originalResponse := map[string]interface{}{
		"user": map[string]interface{}{
			"id":                5,
			"login":             "worker",
			"firstname":         "Worker",
			"lastname":          "Smile",
			"api_key":           "f9bmfqth6vymogzdwy59un452keaq93784hz66ac", // Should be removed
			"passwd_changed_on": "2025-10-07T06:27:38Z",                     // Should be removed
			"twofa_scheme":      nil,                                        // Should be removed
			"last_login_on":     "2025-10-08T16:37:20Z",                     // Should be removed
			"mail":              "worker@example.com",                       // Should be kept
			"admin":             false,                                      // Should be kept
		},
	}

	// Convert to JSON
	originalJSON, _ := json.Marshal(originalResponse)

	// Sanitize
	sanitizedJSON, err := rh.SanitizeUserResponse(originalJSON)
	if err != nil {
		t.Fatalf("SanitizeUserResponse failed: %v", err)
	}

	// Parse sanitized response
	var sanitizedResponse map[string]interface{}
	if err := json.Unmarshal(sanitizedJSON, &sanitizedResponse); err != nil {
		t.Fatalf("Failed to parse sanitized JSON: %v", err)
	}

	user := sanitizedResponse["user"].(map[string]interface{})

	// Check that sensitive fields are removed
	sensitiveFields := []string{"api_key", "passwd_changed_on", "twofa_scheme", "last_login_on"}
	for _, field := range sensitiveFields {
		if _, exists := user[field]; exists {
			t.Errorf("Sensitive field '%s' was not removed from response", field)
		}
	}

	// Check that safe fields are preserved
	safeFields := map[string]interface{}{
		"id":        float64(5),
		"login":     "worker",
		"firstname": "Worker",
		"lastname":  "Smile",
		"mail":      "worker@example.com",
		"admin":     false,
	}

	for field, expectedValue := range safeFields {
		if actualValue, exists := user[field]; !exists {
			t.Errorf("Safe field '%s' was removed from response", field)
		} else if actualValue != expectedValue {
			t.Errorf("Safe field '%s' has wrong value: got %v, want %v", field, actualValue, expectedValue)
		}
	}
}

func TestSanitizeUserResponseDisabled(t *testing.T) {
	// Create config with filtering disabled
	cfg := &config.Config{
		ResponseFilter: config.ResponseFilterConfig{
			Enabled: false, // Disabled
		},
	}

	db := &database.PostgreSQL{}
	log := &logger.Logger{}
	rh := redmine.NewRedmineHandler(cfg, db, log)

	originalJSON := `{"user":{"id":1,"api_key":"secret"}}`
	sanitizedJSON, err := rh.SanitizeUserResponse([]byte(originalJSON))
	if err != nil {
		t.Fatalf("SanitizeUserResponse failed: %v", err)
	}

	// When disabled, response should be unchanged
	if string(sanitizedJSON) != originalJSON {
		t.Errorf("Response was modified when filtering is disabled: got %s, want %s", string(sanitizedJSON), originalJSON)
	}
}

func TestSanitizeUserResponseWithNestedObjects(t *testing.T) {
	cfg := &config.Config{
		ResponseFilter: config.ResponseFilterConfig{
			Enabled:         true,
			SensitiveFields: []string{"api_key"},
		},
	}

	db := &database.PostgreSQL{}
	log := &logger.Logger{}
	rh := redmine.NewRedmineHandler(cfg, db, log)

	// Test with nested user objects (e.g., in issue responses)
	originalResponse := map[string]interface{}{
		"issue": map[string]interface{}{
			"id": 123,
			"author": map[string]interface{}{
				"id":      5,
				"login":   "worker",
				"api_key": "secret", // Should be removed from nested user
			},
			"assigned_to": map[string]interface{}{
				"id":      6,
				"login":   "admin",
				"api_key": "admin_secret", // Should be removed from nested user
			},
		},
	}

	originalJSON, _ := json.Marshal(originalResponse)
	sanitizedJSON, err := rh.SanitizeUserResponse(originalJSON)
	if err != nil {
		t.Fatalf("SanitizeUserResponse failed: %v", err)
	}

	var sanitizedResponse map[string]interface{}
	json.Unmarshal(sanitizedJSON, &sanitizedResponse)

	issue := sanitizedResponse["issue"].(map[string]interface{})
	author := issue["author"].(map[string]interface{})
	assignedTo := issue["assigned_to"].(map[string]interface{})

	// Check that API keys are removed from nested user objects
	if _, exists := author["api_key"]; exists {
		t.Error("api_key was not removed from nested author object")
	}
	if _, exists := assignedTo["api_key"]; exists {
		t.Error("api_key was not removed from nested assigned_to object")
	}

	// Check that other fields are preserved
	if author["login"] != "worker" {
		t.Error("login field was removed from nested author object")
	}
	if assignedTo["login"] != "admin" {
		t.Error("login field was removed from nested assigned_to object")
	}
}

func TestSanitizeUserResponseInvalidJSON(t *testing.T) {
	cfg := &config.Config{
		ResponseFilter: config.ResponseFilterConfig{
			Enabled: true,
		},
	}

	db := &database.PostgreSQL{}
	log := &logger.Logger{}
	rh := redmine.NewRedmineHandler(cfg, db, log)

	// Test with invalid JSON
	invalidJSON := []byte(`{"invalid": json}`)
	sanitizedJSON, err := rh.SanitizeUserResponse(invalidJSON)
	if err != nil {
		t.Fatalf("SanitizeUserResponse should not fail on invalid JSON: %v", err)
	}

	// Should return original body on parse error
	if string(sanitizedJSON) != string(invalidJSON) {
		t.Errorf("Invalid JSON was modified: got %s, want %s", string(sanitizedJSON), string(invalidJSON))
	}
}
