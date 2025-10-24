package redmine

import (
	"context"
	"errors"
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
		c.JSON(http.StatusBadRequest, responses.ErrorResponse{
			Error:            "Invalid query parameters",
			ErrorDescription: err.Error(),
		})
		return
	}

	// Apply defaults for optional parameters
	req.ApplyDefaults()

	// Validate request
	if err := req.Validate(); err != nil {
		rh.handleValidationError(c, "Validation failed", err)
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
		rh.handleValidationError(c, "Invalid date range", err)
		return
	}

	rh.logger.Logger.WithFields(map[string]interface{}{
		"user_id":   userID,
		"from_date": fromDate.Format("2006-01-02"),
		"to_date":   toDate.Format("2006-01-02"),
	}).Info("Processing task involvement request")

	ctx := context.Background()

	// Get total count for pagination metadata
	totalCount, err := rh.db.CountTaskInvolvement(ctx, userID.(int), fromDate, toDate)
	if err != nil {
		rh.logger.Logger.WithFields(map[string]interface{}{
			"error":     err.Error(),
			"user_id":   userID,
			"from_date": fromDate.Format("2006-01-02"),
			"to_date":   toDate.Format("2006-01-02"),
		}).Error("Database count query failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":       "Failed to retrieve task involvement data",
			"description": "An internal error occurred while processing your request",
		})
		return
	}

	// Query with sorting and pagination
	dbResults, err := rh.db.QueryTaskInvolvementWithOptions(
		ctx,
		userID.(int),
		fromDate,
		toDate,
		req.SortBy,
		req.SortOrder,
		req.Limit,
		req.Offset,
	)
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

	// Calculate pagination flags
	hasNext := req.Offset+len(tasks) < totalCount
	hasPrev := req.Offset > 0

	// Build response
	response := responses.TaskInvolvementResponse{
		Data: tasks,
		Metadata: responses.ResponseMetadata{
			TotalCount:  totalCount,
			FromDate:    fromDate.Format("2006-01-02"),
			ToDate:      toDate.Format("2006-01-02"),
			GeneratedAt: time.Now(),
			HasNext:     &hasNext,
			HasPrev:     &hasPrev,
			Limit:       &req.Limit,
			Offset:      &req.Offset,
		},
	}

	// Log query execution time
	duration := time.Since(startTime)
	rh.logger.Logger.WithFields(map[string]interface{}{
		"user_id":      userID,
		"result_count": len(tasks),
		"duration_ms":  duration.Milliseconds(),
	}).Info("Task involvement request completed")

	c.JSON(http.StatusOK, response)
}

func (rh *RedmineHandler) handleValidationError(c *gin.Context, defaultMessage string, err error) {
	var validationErr *requests.ValidationError
	message := defaultMessage
	code := "invalid_request"
	description := err.Error()

	if errors.As(err, &validationErr) {
		description = validationErr.Message
		code = validationErr.Code
		switch validationErr.Code {
		case requests.ErrCodeInvalidDateFormat:
			message = "Invalid date format"
		case requests.ErrCodeInvalidDateRange:
			message = "Invalid date range"
		}
	}

	rh.logger.Logger.WithFields(map[string]interface{}{
		"error":       description,
		"error_code":  code,
		"http_status": http.StatusBadRequest,
	}).Error("Task involvement validation failed")

	c.JSON(http.StatusBadRequest, responses.ErrorResponse{
		Error:            message,
		ErrorCode:        code,
		ErrorDescription: description,
	})
}
