package database

import (
	"context"
	"fmt"
	"time"
)

// TaskInvolvementItem represents a single task with involvement details
type TaskInvolvementItem struct {
	TaskID        int
	Subject       string
	SpentTime     float64
	HaveMyComment int
	StatusChanged int
	StillAssignee int
}

// QueryTaskInvolvement executes the SQL query to retrieve task involvement data
// Returns issues where the user had active involvement during the specified time period
func (p *PostgreSQL) QueryTaskInvolvement(ctx context.Context, userID int, fromDate, toDate time.Time) ([]TaskInvolvementItem, error) {
	query := `
		SELECT DISTINCT
			i.id AS task_id,
			i.subject,
			COALESCE(SUM(te.hours), 0) AS spent_time,
			CASE 
				WHEN EXISTS (
					SELECT 1 
					FROM journals j 
					WHERE j.journalized_id = i.id 
						AND j.journalized_type = 'Issue'
						AND j.user_id = $1
						AND j.notes IS NOT NULL 
						AND j.notes != ''
						AND j.created_on >= $2
						AND j.created_on <= $3
				) THEN 1 
				ELSE 0 
			END AS have_my_comment,
			CASE 
				WHEN EXISTS (
					SELECT 1 
					FROM journals j
					INNER JOIN journal_details jd ON j.id = jd.journal_id
					WHERE j.journalized_id = i.id
						AND j.journalized_type = 'Issue'
						AND jd.property = 'attr'
						AND jd.prop_key = 'status_id'
						AND j.created_on >= $2
						AND j.created_on <= $3
						AND (j.user_id = $1 OR i.assigned_to_id = $1)
				) THEN 1 
				ELSE 0 
			END AS status_changed,
			CASE 
				WHEN i.assigned_to_id = $1 THEN 1 
				ELSE 0 
			END AS still_assignee
		FROM 
			issues i
		LEFT JOIN 
			time_entries te ON te.issue_id = i.id 
				AND te.user_id = $1
				AND te.spent_on >= $2
				AND te.spent_on <= $3
		WHERE 
			-- Currently assigned OR was unassigned from me during this period
			(i.assigned_to_id = $1 
			 OR EXISTS (
				-- Was unassigned from me during this period (I'm in old_value, indicates I was working on it)
				SELECT 1 
				FROM journals j
				INNER JOIN journal_details jd ON j.id = jd.journal_id
				WHERE j.journalized_id = i.id
					AND j.journalized_type = 'Issue'
					AND jd.property = 'attr'
					AND jd.prop_key = 'assigned_to_id'
					AND jd.old_value = CAST($1 AS VARCHAR)
					AND j.created_on >= $2
					AND j.created_on <= $3
			 ))
			-- AND had activity this week
			AND (
				-- Logged time
				EXISTS (
					SELECT 1 
					FROM time_entries te2 
					WHERE te2.issue_id = i.id 
						AND te2.user_id = $1
						AND te2.spent_on >= $2
						AND te2.spent_on <= $3
				)
				-- OR added comment
				OR EXISTS (
					SELECT 1 
					FROM journals j 
					WHERE j.journalized_id = i.id 
						AND j.journalized_type = 'Issue'
						AND j.user_id = $1
						AND j.notes IS NOT NULL 
						AND j.notes != ''
						AND j.created_on >= $2
						AND j.created_on <= $3
				)
				-- OR status was changed (by me or while I was assigned)
				OR EXISTS (
					SELECT 1 
					FROM journals j
					INNER JOIN journal_details jd ON j.id = jd.journal_id
					WHERE j.journalized_id = i.id
						AND j.journalized_type = 'Issue'
						AND jd.property = 'attr'
						AND jd.prop_key = 'status_id'
						AND j.created_on >= $2
						AND j.created_on <= $3
						AND (j.user_id = $1 OR i.assigned_to_id = $1)
				)
				-- OR assignment changed (unassigned from me only, not newly assigned)
				OR EXISTS (
					SELECT 1 
					FROM journals j
					INNER JOIN journal_details jd ON j.id = jd.journal_id
					WHERE j.journalized_id = i.id
						AND j.journalized_type = 'Issue'
						AND jd.property = 'attr'
						AND jd.prop_key = 'assigned_to_id'
						AND jd.old_value = CAST($1 AS VARCHAR)
						AND j.created_on >= $2
						AND j.created_on <= $3
				)
			)
		GROUP BY 
			i.id, i.subject, i.assigned_to_id
		ORDER BY 
			i.id
	`

	// Execute query with 5-second timeout
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := p.QueryContext(queryCtx, query, userID, fromDate, toDate)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer rows.Close()

	var results []TaskInvolvementItem
	for rows.Next() {
		var item TaskInvolvementItem
		err := rows.Scan(
			&item.TaskID,
			&item.Subject,
			&item.SpentTime,
			&item.HaveMyComment,
			&item.StatusChanged,
			&item.StillAssignee,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		results = append(results, item)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	// Return empty array instead of nil for consistency
	if results == nil {
		results = []TaskInvolvementItem{}
	}

	return results, nil
}
