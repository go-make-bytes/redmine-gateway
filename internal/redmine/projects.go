package redmine

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
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
