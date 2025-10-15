package redmine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetCurrentUser returns information about the authenticated user by proxying to Redmine API
func (rh *RedmineHandler) GetCurrentUser(c *gin.Context) {
	ctx := context.Background()

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user to retrieve API key
	user, err := rh.db.GetUserByID(ctx, userID.(int))
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to get user for current user API")
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

	// Proxy request to Redmine's /users/current.json API
	targetURL := fmt.Sprintf("%s/users/current.json", rh.cfg.Redmine.BaseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to create current user request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create current user request"})
		return
	}

	// Add Redmine API key
	req.Header.Set("X-Redmine-API-Key", user.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Make request to Redmine
	resp, err := rh.client.Do(req)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Current user API request failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to connect to Redmine API"})
		return
	}
	defer resp.Body.Close()

	// Check for REST API disabled scenarios
	if resp.StatusCode == http.StatusNotFound {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":         "REST API is not enabled",
			"error_code":    "rest_api_disabled",
			"description":   "The API endpoint was not found. REST API may be disabled.",
			"help":          "Enable REST API in Redmine: Administration → Settings → API → Enable REST web service",
			"documentation": "https://www.redmine.org/projects/redmine/wiki/Rest_api#Enable-REST-API",
		})
		return
	}

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to read current user API response")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to read Redmine API response"})
		return
	}

	// Parse the response to extract the user object
	var redmineResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &redmineResponse); err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to parse Redmine response")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to parse Redmine response"})
		return
	}

	// Return just the user object (not wrapped) - let Gin handle headers automatically
	if user, ok := redmineResponse["user"]; ok {
		c.JSON(http.StatusOK, user)
	} else {
		rh.logger.Logger.Error("No user object in Redmine response")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Invalid response format from Redmine"})
	}
}
