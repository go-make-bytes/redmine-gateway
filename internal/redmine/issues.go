package redmine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GetIssues returns issues accessible by the authenticated user
func (rh *RedmineHandler) GetIssues(c *gin.Context) {
	ctx := context.Background()

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Parse pagination parameters
	limit := 25
	offset := 0

	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	// Parse filters
	filters := make(map[string]string)
	if statusID := c.Query("status_id"); statusID != "" {
		filters["status_id"] = statusID
	}
	if projectID := c.Query("project_id"); projectID != "" {
		filters["project_id"] = projectID
	}
	if assignedToID := c.Query("assigned_to_id"); assignedToID != "" {
		filters["assigned_to_id"] = assignedToID
	}

	issues, totalCount, err := rh.db.GetUserIssues(ctx, userID.(int), limit, offset, filters)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to get user issues")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve issues"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"issues":      issues,
		"total_count": totalCount,
		"offset":      offset,
		"limit":       limit,
	})
}

// CreateIssueViaAPI creates an issue using Redmine API (example of write operation)
func (rh *RedmineHandler) CreateIssueViaAPI(c *gin.Context) {
	ctx := context.Background()

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user to retrieve API key
	user, err := rh.db.GetUserByID(ctx, userID.(int))
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to get user for issue creation")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
		return
	}

	if user.APIKey == "" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "User has no API key. Please generate one in Redmine: My account → API access key → Show",
			"help":  "Visit your Redmine profile to generate an API key first",
		})
		return
	}

	// Read request body
	var issueData map[string]interface{}
	if err := c.ShouldBindJSON(&issueData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issue data"})
		return
	}

	// Convert to JSON
	jsonData, err := json.Marshal(issueData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issue data format"})
		return
	}

	// Create request to Redmine API
	targetURL := fmt.Sprintf("%s/issues.json", rh.cfg.Redmine.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewBuffer(jsonData))
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to create issue request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create issue request"})
		return
	}

	req.Header.Set("X-Redmine-API-Key", user.APIKey)
	req.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := rh.client.Do(req)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Issue creation request failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to connect to Redmine API"})
		return
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to read issue creation response")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to read Redmine API response"})
		return
	}

	// Parse response
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		c.Data(resp.StatusCode, "application/json", respBody)
		return
	}

	rh.logger.Logger.WithFields(map[string]interface{}{
		"user_id":         userID,
		"response_status": resp.StatusCode,
	}).Info("Issue created via API")
	c.JSON(resp.StatusCode, result)
}

// GetAllowedStatusesForIssue returns the allowed status transitions for a given issue
// This queries the workflows table directly and works for both OSS Redmine and EasyRedmine
// Query parameters:
//   - issue_id: The ID of the issue (required)
func (rh *RedmineHandler) GetAllowedStatusesForIssue(c *gin.Context) {
	ctx := context.Background()

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get issue_id from query parameter
	issueIDStr := c.Query("issue_id")
	if issueIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":       "Missing required parameter",
			"description": "issue_id parameter is required",
		})
		return
	}

	issueID, err := strconv.Atoi(issueIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":       "Invalid issue_id",
			"description": "issue_id must be a valid integer",
		})
		return
	}

	// Query the database for allowed statuses
	statuses, err := rh.db.GetAllowedStatusesForIssue(ctx, issueID, userID.(int))
	if err != nil {
		rh.logger.Logger.WithFields(map[string]interface{}{
			"error":    err.Error(),
			"issue_id": issueID,
			"user_id":  userID,
		}).Error("Failed to get allowed statuses for issue")
		
		// Check if it's a "not found" error
		if err.Error() == "issue not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":       "Issue not found",
				"description": "The specified issue does not exist",
			})
			return
		}
		
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":       "Failed to retrieve allowed statuses",
			"description": "An error occurred while querying allowed status transitions",
		})
		return
	}

	// Return the statuses in a format similar to Redmine API
	c.JSON(http.StatusOK, gin.H{
		"allowed_statuses": statuses,
	})
}

