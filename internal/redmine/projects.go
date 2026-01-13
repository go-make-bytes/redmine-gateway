package redmine

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-make-bytes/redmine-gateway/internal/router/responses"
)

// GetProjects returns projects accessible by the authenticated user
func (rh *RedmineHandler) GetProjects(c *gin.Context) {
	ctx := context.Background()

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	projects, err := rh.db.GetUserProjects(ctx, userID.(int))
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to get user projects")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve projects"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"projects":    projects,
		"total_count": len(projects),
		"offset":      0,
		"limit":       len(projects),
	})
}

// GetAssignableUsers returns users and groups that can be assigned to issues in a project
func (rh *RedmineHandler) GetAssignableUsers(c *gin.Context) {
	ctx := context.Background()

	// Check authentication
	_, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get project ID from URL parameter
	projectIDStr := c.Param("id")
	projectID, err := strconv.Atoi(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
		return
	}

	// Get assignable users from database
	users, err := rh.db.GetAssignableUsers(ctx, projectID)
	if err != nil {
		rh.logger.Logger.WithField("error", err.Error()).Error("Failed to get assignable users")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve assignable users"})
		return
	}

	// Convert to response format
	responseUsers := make([]responses.AssignableUser, len(users))
	for i, user := range users {
		responseUsers[i] = responses.AssignableUser{
			ID:   user.ID,
			Name: user.Name,
			Type: user.Type,
		}
	}

	c.JSON(http.StatusOK, responseUsers)
}
