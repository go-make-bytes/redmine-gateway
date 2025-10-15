package redmine

import (
	"bytes"
	"context"
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
	rh.logger.Logger.WithField("url", targetURL).WithField("method", c.Request.Method).WithField("headers", c.Request.Header).Info("Proxying request to Redmine")

	// Make request to Redmine
	resp, err := rh.client.Do(req)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Redmine API request failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to connect to Redmine API"})
		return
	}
	defer resp.Body.Close()

	// Log response status
	rh.logger.Logger.WithField("status", resp.StatusCode).Info("Redmine API response received")

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
	rh.logger.Logger.WithField("body_preview", bodyPreview).Info("Redmine API response body")

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

	// Use a test API key if available in config
	if rh.cfg.Redmine.TestAPIKey != "" {
		req.Header.Set("X-Redmine-API-Key", rh.cfg.Redmine.TestAPIKey)
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

		// Fallback: try to check via HTTP request
		return rh.checkRestAPIEnabledViaHTTP()
	}

	// Convert string to boolean (Redmine stores "1" for enabled, "0" for disabled)
	enabled := apiEnabled == "1"

	rh.logger.Logger.WithField("rest_api_enabled", enabled).Info("REST API status checked from database")

	return enabled, nil
}

// checkRestAPIEnabledViaHTTP checks if Redmine REST API is enabled by testing an endpoint (fallback method)
func (rh *RedmineHandler) checkRestAPIEnabledViaHTTP() (bool, error) {
	ctx := context.Background()

	// Test a simple endpoint that should work if REST API is enabled
	// We'll try the /projects.json endpoint without authentication
	testURL := fmt.Sprintf("%s/projects.json", rh.cfg.Redmine.BaseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create test request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to connect to Redmine: %w", err)
	}
	defer resp.Body.Close()

	// If we get 401 (Unauthorized), REST API is enabled but requires auth
	// If we get 403 (Forbidden) with specific error, REST API might be disabled
	// If we get 404 (Not Found), REST API is disabled
	// If we get 200, REST API is enabled and accessible

	switch resp.StatusCode {
	case http.StatusOK, http.StatusUnauthorized:
		// 200: API enabled and accessible
		// 401: API enabled but requires authentication
		return true, nil
	case http.StatusNotFound:
		// 404: REST API is disabled
		return false, nil
	case http.StatusForbidden:
		// 403: Could be REST API disabled or other permissions issue
		// Read response body to check if it mentions REST API
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read response body: %w", err)
		}

		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "rest") || strings.Contains(bodyStr, "api") {
			return false, nil
		}

		// If no mention of REST/API in error, assume it's a permission issue
		// and REST API is enabled
		return true, nil
	default:
		// Other status codes - assume REST API is enabled but there's another issue
		return true, nil
	}
}

// DiagnosticCheck provides comprehensive diagnostic information about Redmine configuration
func (rh *RedmineHandler) DiagnosticCheck(c *gin.Context) {
	ctx := context.Background()

	result := gin.H{
		"timestamp":   time.Now(),
		"service":     "oauth-redmine-proxy",
		"redmine_url": rh.cfg.Redmine.BaseURL,
		"checks":      gin.H{},
	}

	checks := result["checks"].(gin.H)

	// Check 1: Database connectivity
	err := rh.db.PingContext(ctx)
	if err != nil {
		checks["database"] = gin.H{
			"status": "failed",
			"error":  err.Error(),
		}
	} else {
		checks["database"] = gin.H{
			"status": "ok",
		}
	}

	// Check 2: REST API status from database
	restAPIEnabled, err := rh.checkRestAPIEnabled()
	if err != nil {
		checks["rest_api"] = gin.H{
			"status": "error",
			"error":  err.Error(),
		}
	} else {
		checks["rest_api"] = gin.H{
			"status":  "ok",
			"enabled": restAPIEnabled,
		}

		if !restAPIEnabled {
			checks["rest_api"].(gin.H)["warning"] = "REST API is disabled. Contact your administrator to enable it in Redmine settings."
			checks["rest_api"].(gin.H)["admin_note"] = "Enable in: Administration → Settings → API → Enable REST web service"
		}
	}

	// Check 3: Redmine connectivity
	testURL := fmt.Sprintf("%s/", rh.cfg.Redmine.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		checks["redmine_connectivity"] = gin.H{
			"status": "failed",
			"error":  "Failed to create request: " + err.Error(),
		}
	} else {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			checks["redmine_connectivity"] = gin.H{
				"status": "failed",
				"error":  "Connection failed: " + err.Error(),
			}
		} else {
			resp.Body.Close()
			checks["redmine_connectivity"] = gin.H{
				"status":      "ok",
				"status_code": resp.StatusCode,
			}
		}
	}

	// Check 4: Sample API endpoint test
	if restAPIEnabled {
		apiTestURL := fmt.Sprintf("%s/projects.json", rh.cfg.Redmine.BaseURL)
		req, err := http.NewRequestWithContext(ctx, "GET", apiTestURL, nil)
		if err != nil {
			checks["api_endpoint"] = gin.H{
				"status": "failed",
				"error":  "Failed to create API request: " + err.Error(),
			}
		} else {
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				checks["api_endpoint"] = gin.H{
					"status": "failed",
					"error":  "API request failed: " + err.Error(),
				}
			} else {
				resp.Body.Close()
				checks["api_endpoint"] = gin.H{
					"status":      "ok",
					"status_code": resp.StatusCode,
					"note":        "401 is expected without authentication",
				}
			}
		}
	} else {
		checks["api_endpoint"] = gin.H{
			"status": "skipped",
			"reason": "REST API is disabled",
		}
	}

	// Overall status
	overallStatus := "healthy"
	for _, check := range checks {
		if checkMap, ok := check.(gin.H); ok {
			if status, exists := checkMap["status"]; exists && status == "failed" {
				overallStatus = "degraded"
				break
			}
		}
	}

	result["overall_status"] = overallStatus

	// Return appropriate HTTP status
	if overallStatus == "healthy" {
		c.JSON(http.StatusOK, result)
	} else {
		c.JSON(http.StatusServiceUnavailable, result)
	}
}
