package redmine

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-make-bytes/redmine-gateway/internal/router/requests"
	"github.com/go-make-bytes/redmine-gateway/internal/router/responses"
)

// GetTaskInvolvement handles GET /api/reports/task-involvement
// Returns issues where the authenticated user had active involvement during a specified time period
func (rh *RedmineHandler) GetTaskInvolvement(c *gin.Context) {
	startTime := time.Now()

	var req requests.TaskInvolvementRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Invalid query parameters")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":       "Invalid query parameters",
			"description": err.Error(),
		})
		return
	}

	// Apply defaults for optional parameters
	req.ApplyDefaults()

	// Validate request
	if err := req.Validate(); err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Validation failed")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":       "Validation failed",
			"description": err.Error(),
		})
		return
	}

	// Get authenticated user ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get date range
	fromDate, toDate, err := req.GetDateRange()
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to parse date range")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":       "Invalid date range",
			"description": err.Error(),
		})
		return
	}

	rh.logger.Logger.WithFields(map[string]interface{}{
		"user_id":   userID,
		"from_date": fromDate.Format("2006-01-02"),
		"to_date":   toDate.Format("2006-01-02"),
	}).Info("Processing task involvement request")

	ctx := context.Background()
	dbResults, err := rh.db.QueryTaskInvolvement(ctx, userID.(int), fromDate, toDate)
	if err != nil {
		rh.logger.Logger.WithFields(map[string]interface{}{
			"error":     err.Error(),
			"user_id":   userID,
			"from_date": fromDate.Format("2006-01-02"),
			"to_date":   toDate.Format("2006-01-02"),
		}).Error("Database query failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":       "Failed to retrieve task involvement data",
			"description": "An internal error occurred while processing your request",
		})
		return
	}

	// Convert database results to response DTOs
	tasks := make([]responses.TaskInvolvementItem, len(dbResults))
	for i, dbItem := range dbResults {
		tasks[i] = responses.TaskInvolvementItem{
			TaskID:        dbItem.TaskID,
			Subject:       dbItem.Subject,
			SpentTime:     dbItem.SpentTime,
			HaveMyComment: dbItem.HaveMyComment,
			StatusChanged: dbItem.StatusChanged,
			StillAssignee: dbItem.StillAssignee,
		}
	}

	// Build response
	response := responses.TaskInvolvementResponse{
		Data: tasks,
		Metadata: responses.ResponseMetadata{
			TotalCount:  len(tasks),
			FromDate:    fromDate.Format("2006-01-02"),
			ToDate:      toDate.Format("2006-01-02"),
			GeneratedAt: time.Now(),
		},
	}

	//Log query execution time
	duration := time.Since(startTime)
	rh.logger.Logger.WithFields(map[string]interface{}{
		"user_id":      userID,
		"result_count": len(tasks),
		"duration_ms":  duration.Milliseconds(),
	}).Info("Task involvement request completed")

	c.JSON(http.StatusOK, response)
}
