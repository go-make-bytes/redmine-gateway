package redmine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetEnrichedTimeEntries fetches time entries and enriches them with issue subjects
// This solves the problem of time_entries API only returning issue IDs without subjects
func (rh *RedmineHandler) GetEnrichedTimeEntries(c *gin.Context) {
	ctx := context.Background()

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user to retrieve API key
	user, err := rh.db.GetUserByID(ctx, userID.(int))
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to get user for enriched time entries")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
		return
	}

	if user.APIKey == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "User has no API key"})
		return
	}

	// Build time_entries request URL with all query parameters
	timeEntriesURL := fmt.Sprintf("%s/time_entries.json", rh.cfg.Redmine.BaseURL)
	if c.Request.URL.RawQuery != "" {
		timeEntriesURL += "?" + c.Request.URL.RawQuery
	}

	// Fetch time entries from Redmine
	req, err := http.NewRequestWithContext(ctx, "GET", timeEntriesURL, nil)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to create time entries request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Set("X-Redmine-API-Key", user.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := rh.client.Do(req)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Time entries request failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to connect to Redmine API"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
		return
	}

	// Parse time entries response
	var timeEntriesData struct {
		TimeEntries []map[string]interface{} `json:"time_entries"`
		TotalCount  int                      `json:"total_count"`
		Offset      int                      `json:"offset"`
		Limit       int                      `json:"limit"`
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to read time entries response")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to read response"})
		return
	}

	if err := json.Unmarshal(respBody, &timeEntriesData); err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to parse time entries response")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	// Extract unique issue IDs
	issueIDsMap := make(map[int]bool)
	for _, entry := range timeEntriesData.TimeEntries {
		if issue, ok := entry["issue"].(map[string]interface{}); ok {
			if issueID, ok := issue["id"].(float64); ok {
				issueIDsMap[int(issueID)] = true
			}
		}
	}

	// Convert to slice
	issueIDs := make([]int, 0, len(issueIDsMap))
	for id := range issueIDsMap {
		issueIDs = append(issueIDs, id)
	}

	// Fetch issue subjects directly from database (much more efficient than API calls)
	issueSubjects := make(map[int]string)
	if len(issueIDs) > 0 {
		subjects, err := rh.db.GetIssueSubjects(ctx, issueIDs)
		if err != nil {
			rh.logger.Logger.WithField("error", err.Error()).Error("Failed to fetch issue subjects from database")
			// Continue without subjects rather than failing the entire request
		} else {
			issueSubjects = subjects
			rh.logger.Logger.WithField("issue_count", len(issueSubjects)).Info("Fetched issue subjects from database for time entries")
		}
	}

	// Enrich time entries with issue subjects
	for i := range timeEntriesData.TimeEntries {
		if issue, ok := timeEntriesData.TimeEntries[i]["issue"].(map[string]interface{}); ok {
			if issueID, ok := issue["id"].(float64); ok {
				if subject, found := issueSubjects[int(issueID)]; found {
					issue["subject"] = subject
				}
			}
		}
	}

	// Return enriched response
	c.JSON(http.StatusOK, gin.H{
		"time_entries": timeEntriesData.TimeEntries,
		"total_count":  timeEntriesData.TotalCount,
		"offset":       timeEntriesData.Offset,
		"limit":        timeEntriesData.Limit,
	})
}
