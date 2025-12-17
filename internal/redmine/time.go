package redmine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// CreateTimeEntry creates a new time entry in Redmine
func (rh *RedmineHandler) CreateTimeEntry(c *gin.Context) {
	ctx := context.Background()

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user to retrieve API key
	user, err := rh.db.GetUserByID(ctx, userID.(int))
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to get user for creating time entry")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
		return
	}

	if user.APIKey == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "User has no API key"})
		return
	}

	// Read request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to read request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Build Redmine time_entries URL
	timeEntriesURL := fmt.Sprintf("%s/time_entries.json", rh.cfg.Redmine.BaseURL)

	// Create POST request to Redmine
	req, err := http.NewRequestWithContext(ctx, "POST", timeEntriesURL, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to create time entry request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Set("X-Redmine-API-Key", user.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := rh.client.Do(req)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Time entry creation request failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to connect to Redmine API"})
		return
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to read time entry creation response")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to read response"})
		return
	}

	// Log error details if creation failed
	if resp.StatusCode != http.StatusCreated {
		rh.logger.Logger.WithFields(map[string]interface{}{
			"status_code":   resp.StatusCode,
			"response_body": string(respBody),
			"request_body":  string(body),
		}).Error("Time entry creation failed")
	}

	// Return the response from Redmine
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
}
