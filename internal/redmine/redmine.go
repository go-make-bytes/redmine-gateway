package redmine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/go-make-bytes/redmine-gateway/internal/database"
	"github.com/go-make-bytes/redmine-gateway/internal/logger"
)

type RedmineHandler struct {
	cfg    *config.Config
	db     *database.PostgreSQL
	logger *logger.Logger
	client *http.Client
}

func NewRedmineHandler(cfg *config.Config, db *database.PostgreSQL, logger *logger.Logger) *RedmineHandler {
	return &RedmineHandler{
		cfg:    cfg,
		db:     db,
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ProxyRedmineAPI proxies requests to Redmine API using user's API key
func (rh *RedmineHandler) ProxyRedmineAPI(c *gin.Context) {
	ctx := context.Background()

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user to retrieve API key
	user, err := rh.db.GetUserByID(ctx, userID.(int))
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to get user for API proxy")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
		return
	}

	if user.APIKey == "" {
		// Check if REST API is enabled first
		restAPIEnabled, err := rh.checkRestAPIEnabled()
		if err != nil {
			rh.logger.Logger.WithField("error", err.Error()).Error("Failed to check REST API status")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check Redmine API status"})
			return
		}

		if !restAPIEnabled {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":         "REST API is not enabled",
				"error_code":    "rest_api_disabled",
				"description":   "Redmine REST API must be enabled before using this service",
				"help":          "Contact your administrator to enable Redmine REST API in settings",
				"admin_help":    "Enable REST API in Redmine: Administration → Settings → API → Enable REST web service",
				"documentation": "https://www.redmine.org/projects/redmine/wiki/Rest_api#Enable-REST-API",
			})
			return
		}

		// REST API is enabled but user has no API key - generate one automatically
		rh.logger.Logger.WithField("user_id", user.ID).Info("User has no API key, generating one automatically")

		apiKey, err := rh.db.GenerateAPIKey(ctx, user.ID)
		if err != nil {
			rh.logger.Logger.WithField("error", err.Error()).WithField("user_id", user.ID).Error("Failed to generate API key")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":       "Failed to generate API key",
				"error_code":  "api_key_generation_failed",
				"description": "Could not generate API key for user",
			})
			return
		}

		// Update user object with new API key
		user.APIKey = apiKey
		rh.logger.Logger.WithField("user_id", user.ID).Info("API key generated successfully")
	}

	// Build target URL - remove /api prefix and add .json suffix if not present
	targetPath := strings.TrimPrefix(c.Request.URL.Path, "/api")

	// Add .json suffix if not already present and not an upload/download endpoint
	if !strings.HasSuffix(targetPath, ".json") &&
		!strings.Contains(targetPath, "/uploads") &&
		!strings.Contains(targetPath, "/attachments/") {
		if strings.Contains(targetPath, "?") {
			targetPath = strings.Replace(targetPath, "?", ".json?", 1)
		} else {
			targetPath += ".json"
		}
	}

	targetURL := fmt.Sprintf("%s%s", rh.cfg.Redmine.BaseURL, targetPath)

	// Add query parameters
	if c.Request.URL.RawQuery != "" {
		targetURL += "?" + c.Request.URL.RawQuery
	}

	// Create new request
	var body io.Reader
	if c.Request.Body != nil {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			return
		}
		body = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, c.Request.Method, targetURL, body)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to create proxy request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create proxy request"})
		return
	}

	// Copy headers (except Authorization and cache-related headers)
	for key, values := range c.Request.Header {
		lowerKey := strings.ToLower(key)
		// Skip authorization and cache-related headers
		if lowerKey == "authorization" || lowerKey == "if-none-match" || lowerKey == "if-modified-since" {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Add Redmine API key
	req.Header.Set("X-Redmine-API-Key", user.APIKey)
	req.Header.Set("Content-Type", "application/json")

	// Log the request details
	rh.logger.Logger.WithField("url", targetURL).WithField("method", c.Request.Method).WithField("headers", c.Request.Header).Debug("Proxying request to Redmine")

	// Make request to Redmine
	resp, err := rh.client.Do(req)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Redmine API request failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to connect to Redmine API"})
		return
	}
	defer resp.Body.Close()

	// Log response status
	rh.logger.Logger.WithField("status", resp.StatusCode).Debug("Redmine API response received")

	// Check for REST API disabled scenarios
	if resp.StatusCode == http.StatusNotFound {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":         "REST API is not enabled",
			"error_code":    "rest_api_disabled",
			"description":   "The requested API endpoint was not found. REST API may be disabled.",
			"help":          "Enable REST API in Redmine: Administration → Settings → API → Enable REST web service",
			"documentation": "https://www.redmine.org/projects/redmine/wiki/Rest_api#Enable-REST-API",
		})
		return
	}

	// Copy response headers (excluding caching headers to prevent 304 issues)
	for key, values := range resp.Header {
		// Skip cache-related headers to prevent 304 responses
		lowerKey := strings.ToLower(key)
		if lowerKey == "etag" || lowerKey == "last-modified" || lowerKey == "cache-control" {
			continue
		}
		for _, value := range values {
			c.Header(key, value)
		}
	}

	// Copy response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to read Redmine API response")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to read Redmine API response"})
		return
	}

	// Log response body for debugging (first 500 chars)
	bodyPreview := string(respBody)
	if len(bodyPreview) > 500 {
		bodyPreview = bodyPreview[:500] + "..."
	}
	rh.logger.Logger.WithField("body_preview", bodyPreview).Debug("Redmine API response body")

	// Apply response filtering for user endpoints to remove sensitive data
	if rh.IsUserEndpoint(c.Request.URL.Path) {
		filteredBody, err := rh.SanitizeUserResponse(respBody)
		if err != nil {
			rh.logger.Logger.WithField("error", err.Error()).Error("Failed to sanitize user response")
			// Continue with original body rather than failing the request
		} else {
			respBody = filteredBody
			rh.logger.Logger.WithField("endpoint", c.Request.URL.Path).Info("Applied response filtering for user endpoint")

			// Add security headers for user endpoints to prevent caching of sensitive data
			c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")

			// Audit logging for admin access to user profiles
			if userID, exists := c.Get("user_id"); exists {
				rh.logger.Logger.WithFields(map[string]interface{}{
					"action":          "user_profile_access",
					"requesting_user": userID,
					"endpoint":        c.Request.URL.Path,
					"filtered":        true,
				}).Info("Admin or user accessed profile with sensitive data filtering applied")
			}
		}
	}

	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
}

// ValidateRedmineConnection checks if Redmine API is accessible
func (rh *RedmineHandler) ValidateRedmineConnection(c *gin.Context) {
	ctx := context.Background()

	// Try to connect to Redmine API
	testURL := fmt.Sprintf("%s/users/current.json", rh.cfg.Redmine.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  "Failed to create test request",
		})
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"status": "error",
			"error":  fmt.Sprintf("Connection failed: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		c.JSON(http.StatusOK, gin.H{
			"status":      "connected",
			"redmine_url": rh.cfg.Redmine.BaseURL,
			"timestamp":   time.Now(),
		})
	} else {
		c.JSON(http.StatusBadGateway, gin.H{
			"status":        "error",
			"error":         "Redmine API not accessible",
			"response_code": resp.StatusCode,
			"redmine_url":   rh.cfg.Redmine.BaseURL,
		})
	}
}

// checkRestAPIEnabled checks if Redmine REST API is enabled by querying the settings table
func (rh *RedmineHandler) checkRestAPIEnabled() (bool, error) {
	ctx := context.Background()

	// Query the settings table directly to check if REST API is enabled
	query := `
		SELECT COALESCE(s.value, '0') as api_enabled
		FROM (SELECT '0' as value) as default_value
		LEFT JOIN settings s ON s.name = 'rest_api_enabled'
		LIMIT 1
	`

	var apiEnabled string
	err := rh.db.QueryRowContext(ctx, query).Scan(&apiEnabled)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to query REST API setting from database")
		return false, fmt.Errorf("failed to check REST API status: %w", err)
	}

	// Convert string to boolean (Redmine stores "1" for enabled, "0" for disabled)
	enabled := apiEnabled == "1"

	rh.logger.Logger.WithField("rest_api_enabled", enabled).Info("REST API status checked from database")

	return enabled, nil
}

// IsUserEndpoint checks if the request path is a user detail endpoint that may expose sensitive data
func (rh *RedmineHandler) IsUserEndpoint(path string) bool {
	// Only user detail endpoints expose API keys and sensitive fields
	// User list endpoint (/api/users) does NOT expose API keys per Redmine's design
	return strings.HasPrefix(path, "/api/users/") || path == "/api/users/current"
}

// SanitizeUserResponse removes sensitive fields from user API responses
func (rh *RedmineHandler) SanitizeUserResponse(body []byte) ([]byte, error) {
	if !rh.cfg.ResponseFilter.Enabled {
		return body, nil
	}

	// Parse the JSON response
	var response interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		if rh.logger != nil && rh.logger.Logger != nil {
			rh.logger.Logger.WithField("error", err.Error()).Warn("Failed to parse JSON response for sanitization")
		}
		return body, nil // Return original body on parse error
	}

	// Recursively remove sensitive fields
	sanitized := rh.removeSensitiveFields(response)

	// Convert back to JSON
	sanitizedBody, err := json.Marshal(sanitized)
	if err != nil {
		if rh.logger != nil && rh.logger.Logger != nil {
			rh.logger.Logger.WithField("error", err.Error()).Warn("Failed to marshal sanitized response")
		}
		return body, nil // Return original body on marshal error
	}

	return sanitizedBody, nil
}

// removeSensitiveFields recursively removes sensitive fields from JSON data
func (rh *RedmineHandler) removeSensitiveFields(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		// Remove sensitive fields from objects
		for _, field := range append(rh.cfg.ResponseFilter.SensitiveFields, rh.cfg.ResponseFilter.PrivacyFields...) {
			delete(v, field)
		}
		// Recursively process nested objects
		for key, value := range v {
			v[key] = rh.removeSensitiveFields(value)
		}
		return v
	case []interface{}:
		// Process arrays (for nested user objects in complex responses)
		for i, item := range v {
			v[i] = rh.removeSensitiveFields(item)
		}
		return v
	default:
		return v
	}
}
