package database

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

type PostgreSQL struct {
	db           *sql.DB
	platformInfo *PlatformInfo
}

type User struct {
	ID                 int        `json:"id"`
	Login              string     `json:"login"`
	Firstname          string     `json:"firstname"`
	Lastname           string     `json:"lastname"`
	Mail               string     `json:"mail"`
	AuthSourceID       *int       `json:"auth_source_id,omitempty"` // NULL for database users, LDAP source ID for LDAP users
	Status             int        `json:"status"`
	CreatedOn          time.Time  `json:"created_on"`
	UpdatedOn          time.Time  `json:"updated_on"`
	APIKey             string     `json:"api_key,omitempty"`
	MustChangePassword bool       `json:"must_change_password"`
	PasswdChangedOn    *time.Time `json:"passwd_changed_on,omitempty"`
}

type Project struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Identifier  string `json:"identifier"`
	Description string `json:"description"`
	Status      int    `json:"status"`
}

type Issue struct {
	ID           int        `json:"id"`
	Subject      string     `json:"subject"`
	Description  string     `json:"description"`
	StatusID     int        `json:"status_id"`
	PriorityID   int        `json:"priority_id"`
	ProjectID    int        `json:"project_id"`
	TrackerID    int        `json:"tracker_id"`
	AuthorID     int        `json:"author_id"`
	AssignedToID *int       `json:"assigned_to_id"`
	CreatedOn    time.Time  `json:"created_on"`
	UpdatedOn    time.Time  `json:"updated_on"`
	DueDate      *time.Time `json:"due_date"`
}

func NewPostgreSQL(connectionString string) (*PostgreSQL, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PostgreSQL{
		db:           db,
		platformInfo: nil, // Will be set via SetPlatformInfo after creation
	}, nil
}

func (p *PostgreSQL) Close() error {
	return p.db.Close()
}

// PingContext pings the database to check connectivity
func (p *PostgreSQL) PingContext(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

// AssignableUser represents a principal (user or group) that can be assigned to issues
type AssignableUser struct {
	ID   int
	Name string
	Type string
}

// GetAssignableUsers returns users and groups that can be assigned to issues in a project
func (p *PostgreSQL) GetAssignableUsers(ctx context.Context, projectID int) ([]AssignableUser, error) {
	query := `
		SELECT DISTINCT u.id, 
		       CASE WHEN u.type = 'User' THEN CONCAT(u.firstname, ' ', u.lastname) ELSE u.lastname END AS name,
		       u.type
		FROM users u
		INNER JOIN members m ON m.user_id = u.id
		INNER JOIN member_roles mr ON mr.member_id = m.id
		INNER JOIN roles r ON r.id = mr.role_id
		WHERE u.status = 1
		  AND u.type IN ('User', 'Group')
		  AND m.project_id = $1
		  AND r.assignable = true
		ORDER BY u.type DESC, name, u.id
	`

	rows, err := p.db.QueryContext(ctx, query, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to query assignable users: %w", err)
	}
	defer rows.Close()

	var users []AssignableUser
	for rows.Next() {
		var user AssignableUser
		if err := rows.Scan(&user.ID, &user.Name, &user.Type); err != nil {
			return nil, fmt.Errorf("failed to scan assignable user: %w", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating assignable users: %w", err)
	}

	return users, nil
}

// QueryRowContext executes a query that is expected to return at most one row
func (p *PostgreSQL) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return p.db.QueryRowContext(ctx, query, args...)
}

// QueryContext executes a query that returns multiple rows
func (p *PostgreSQL) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return p.db.QueryContext(ctx, query, args...)
}

// ExecContext executes a query without returning rows
func (p *PostgreSQL) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return p.db.ExecContext(ctx, query, args...)
}

// AuthenticateUser authenticates user against Redmine PostgreSQL database (case-insensitive login)
func (p *PostgreSQL) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	query := `
		SELECT 
			u.id, u.login, u.firstname, u.lastname, 
			u.hashed_password, u.salt, u.status,
			u.created_on, u.updated_on, u.must_change_passwd,
			u.passwd_changed_on,
			t.value as api_key, t.created_on as api_key_created
		FROM users u
		LEFT JOIN tokens t ON u.id = t.user_id AND t.action = 'api' AND t.value IS NOT NULL
		WHERE LOWER(u.login) = LOWER($1) AND u.status = 1
	`

	var user User
	var hashedPassword, salt string
	var apiKey sql.NullString
	var apiKeyCreated sql.NullTime
	var mustChangePassword sql.NullBool
	var passwdChangedOn sql.NullTime

	err := p.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Login, &user.Firstname, &user.Lastname,
		&hashedPassword, &salt, &user.Status,
		&user.CreatedOn, &user.UpdatedOn, &mustChangePassword,
		&passwdChangedOn,
		&apiKey, &apiKeyCreated,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid username or password")
		}
		return nil, fmt.Errorf("database query failed: %w", err)
	}

	// Set nullable fields
	user.MustChangePassword = mustChangePassword.Valid && mustChangePassword.Bool
	if passwdChangedOn.Valid {
		user.PasswdChangedOn = &passwdChangedOn.Time
	}

	// Set mail to empty string since we don't fetch it from database
	user.Mail = ""

	// Set API key from nullable string
	if apiKey.Valid {
		user.APIKey = apiKey.String
	} else {
		user.APIKey = ""
	}

	// Verify password using Redmine's format: sha1(salt + sha1(password))
	if !p.verifyRedminePassword(password, hashedPassword, salt) {
		return nil, fmt.Errorf("invalid username or password")
	}

	// Note: API keys are generated by Redmine itself when user first accesses their API key
	// We just read the existing API key from the tokens table

	return &user, nil
}

// verifyRedminePassword verifies password using Redmine's hashing algorithm
func (p *PostgreSQL) verifyRedminePassword(password, hashedPassword, salt string) bool {
	// Redmine password hashing: sha1(salt + sha1(password))
	innerHash := fmt.Sprintf("%x", sha1.Sum([]byte(password)))
	outerHash := fmt.Sprintf("%x", sha1.Sum([]byte(salt+innerHash)))
	return outerHash == hashedPassword
}

// GenerateAPIKey generates a new API key for the user
func (p *PostgreSQL) GenerateAPIKey(ctx context.Context, userID int) (string, error) {
	// First, delete any existing API tokens for this user (matching Redmine's behavior)
	deleteQuery := `DELETE FROM tokens WHERE user_id = $1 AND action = 'api'`
	_, err := p.db.ExecContext(ctx, deleteQuery, userID)
	if err != nil {
		return "", fmt.Errorf("failed to delete existing API tokens: %w", err)
	}

	// Generate 40-character API key (same format as Redmine)
	apiKey := generateRandomString(40)

	// Store the new API key in the tokens table
	insertQuery := `
		INSERT INTO tokens (user_id, action, value, created_on, updated_on)
		VALUES ($1, 'api', $2, NOW(), NOW())
		RETURNING value
	`

	var returnedKey string
	err = p.db.QueryRowContext(ctx, insertQuery, userID, apiKey).Scan(&returnedKey)
	if err != nil {
		return "", fmt.Errorf("failed to store API key: %w", err)
	}

	return returnedKey, nil
}

// GetUserByID retrieves user by ID
func (p *PostgreSQL) GetUserByID(ctx context.Context, userID int) (*User, error) {
	query := `
		SELECT
			u.id, u.login, u.firstname, u.lastname,
			COALESCE(ea.address, '') as mail, u.status,
			u.created_on, u.updated_on, u.must_change_passwd,
			t.value as api_key
		FROM users u
		LEFT JOIN email_addresses ea ON u.id = ea.user_id AND ea.is_default = true
		LEFT JOIN tokens t ON u.id = t.user_id AND t.action = 'api'
		WHERE u.id = $1 AND u.status = 1
	`

	var user User
	var apiKey sql.NullString
	var mustChangePassword sql.NullBool
	err := p.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID, &user.Login, &user.Firstname, &user.Lastname, &user.Mail, &user.Status,
		&user.CreatedOn, &user.UpdatedOn, &mustChangePassword, &apiKey,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("database query failed: %w", err)
	}

	// Set MustChangePassword from nullable bool
	user.MustChangePassword = mustChangePassword.Valid && mustChangePassword.Bool

	// Set API key from nullable string
	if apiKey.Valid {
		user.APIKey = apiKey.String
	} else {
		user.APIKey = ""
	}

	return &user, nil
}

// GetUserProjects retrieves projects accessible by the user
func (p *PostgreSQL) GetUserProjects(ctx context.Context, userID int) ([]*Project, error) {
	query := `
		SELECT DISTINCT p.id, p.name, p.identifier, p.description, p.status
		FROM projects p
		JOIN members m ON p.id = m.project_id
		WHERE m.user_id = $1 AND p.status = 1
		ORDER BY p.name
	`

	rows, err := p.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query projects: %w", err)
	}
	defer rows.Close()

	var projects []*Project
	for rows.Next() {
		var project Project
		err := rows.Scan(&project.ID, &project.Name, &project.Identifier, &project.Description, &project.Status)
		if err != nil {
			return nil, fmt.Errorf("failed to scan project: %w", err)
		}
		projects = append(projects, &project)
	}

	return projects, nil
}

// GetUserIssues retrieves issues accessible by the user with optimized query
func (p *PostgreSQL) GetUserIssues(ctx context.Context, userID int, limit, offset int, filters map[string]string) ([]*Issue, int, error) {
	// Build WHERE clause based on filters
	whereClause := "WHERE i.project_id IN (SELECT DISTINCT m.project_id FROM members m WHERE m.user_id = $1 AND m.project_id IN (SELECT id FROM projects WHERE status = 1))"
	args := []interface{}{userID}
	argIndex := 2

	if statusID, ok := filters["status_id"]; ok && statusID != "" {
		whereClause += fmt.Sprintf(" AND i.status_id = $%d", argIndex)
		args = append(args, statusID)
		argIndex++
	}

	if projectID, ok := filters["project_id"]; ok && projectID != "" {
		whereClause += fmt.Sprintf(" AND i.project_id = $%d", argIndex)
		args = append(args, projectID)
		argIndex++
	}

	if assignedToID, ok := filters["assigned_to_id"]; ok && assignedToID != "" {
		if assignedToID == "me" {
			whereClause += fmt.Sprintf(" AND i.assigned_to_id = $%d", argIndex)
			args = append(args, userID)
		} else {
			whereClause += fmt.Sprintf(" AND i.assigned_to_id = $%d", argIndex)
			args = append(args, assignedToID)
		}
		argIndex++
	}

	// Count query
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM issues i
		%s
	`, whereClause)

	var totalCount int
	err := p.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count issues: %w", err)
	}

	// Main query
	query := fmt.Sprintf(`
		SELECT i.id, i.subject, i.description, i.status_id, i.priority_id,
			   i.project_id, i.tracker_id, i.author_id, i.assigned_to_id,
			   i.created_on, i.updated_on, i.due_date
		FROM issues i
		%s
		ORDER BY i.updated_on DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query issues: %w", err)
	}
	defer rows.Close()

	var issues []*Issue
	for rows.Next() {
		var issue Issue
		err := rows.Scan(
			&issue.ID, &issue.Subject, &issue.Description, &issue.StatusID, &issue.PriorityID,
			&issue.ProjectID, &issue.TrackerID, &issue.AuthorID, &issue.AssignedToID,
			&issue.CreatedOn, &issue.UpdatedOn, &issue.DueDate,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan issue: %w", err)
		}
		issues = append(issues, &issue)
	}

	return issues, totalCount, nil
}

// GetIssueSubjects fetches issue subjects by IDs from the database
// This is used to enrich time entries with issue subjects without making multiple API calls
func (p *PostgreSQL) GetIssueSubjects(ctx context.Context, issueIDs []int) (map[int]string, error) {
	if len(issueIDs) == 0 {
		return make(map[int]string), nil
	}

	// Build query with IN clause
	query := `
		SELECT id, subject 
		FROM issues 
		WHERE id = ANY($1)
	`

	rows, err := p.db.QueryContext(ctx, query, pq.Array(issueIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to query issue subjects: %w", err)
	}
	defer rows.Close()

	subjects := make(map[int]string)
	for rows.Next() {
		var id int
		var subject string
		if err := rows.Scan(&id, &subject); err != nil {
			return nil, fmt.Errorf("failed to scan issue subject: %w", err)
		}
		subjects[id] = subject
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating issue subjects: %w", err)
	}

	return subjects, nil
}

// ChangePassword updates user's password using Redmine's hashing algorithm
// and performs all necessary security updates (token deletion, timestamp updates)
func (p *PostgreSQL) ChangePassword(ctx context.Context, userID int, newPassword string) error {
	// Validate password complexity
	if err := p.ValidatePassword(ctx, newPassword); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	// Generate new salt
	salt := p.generateSalt()

	// Hash password using Redmine's algorithm: sha1(salt + sha1(password))
	innerHash := fmt.Sprintf("%x", sha1.Sum([]byte(newPassword)))
	hashedPassword := fmt.Sprintf("%x", sha1.Sum([]byte(salt+innerHash)))

	// Update password, salt, timestamp, and clear must_change_passwd flag
	updateQuery := `
		UPDATE users 
		SET hashed_password = $1, salt = $2, passwd_changed_on = NOW(), must_change_passwd = false, updated_on = NOW()
		WHERE id = $3
	`

	_, err := p.db.ExecContext(ctx, updateQuery, hashedPassword, salt, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Delete recovery, autologin, and session tokens (Redmine security practice)
	deleteTokensQuery := `DELETE FROM tokens WHERE user_id = $1 AND action IN ('recovery', 'autologin', 'session')`
	_, err = p.db.ExecContext(ctx, deleteTokensQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to delete tokens: %w", err)
	}

	return nil
}

// GetPasswordSettings retrieves password complexity settings from Redmine
func (p *PostgreSQL) GetPasswordSettings(ctx context.Context) (minLength int, requiredCharClasses []string, err error) {
	// Default values
	minLength = 12
	requiredCharClasses = []string{"lowercase", "uppercase", "numbers"}

	// Try to read from settings table
	minLengthQuery := `SELECT value FROM settings WHERE name = 'password_min_length'`
	var minLengthStr sql.NullString
	err = p.db.QueryRowContext(ctx, minLengthQuery).Scan(&minLengthStr)
	if err == nil && minLengthStr.Valid {
		if parsed, parseErr := strconv.Atoi(minLengthStr.String); parseErr == nil && parsed > 0 {
			minLength = parsed
		}
	}

	charClassesQuery := `SELECT value FROM settings WHERE name = 'password_required_char_classes'`
	var charClassesStr sql.NullString
	err = p.db.QueryRowContext(ctx, charClassesQuery).Scan(&charClassesStr)
	if err == nil && charClassesStr.Valid && charClassesStr.String != "" {
		// Parse the serialized array (Redmine stores it as YAML)
		// For simplicity, we'll handle common cases
		if charClassesStr.String != "--- []" && charClassesStr.String != "---\n" {
			// If we have actual requirements, use them
			// This is a simplified parsing - in production you might want proper YAML parsing
			requiredCharClasses = []string{}
			if strings.Contains(charClassesStr.String, "lowercase") {
				requiredCharClasses = append(requiredCharClasses, "lowercase")
			}
			if strings.Contains(charClassesStr.String, "uppercase") {
				requiredCharClasses = append(requiredCharClasses, "uppercase")
			}
			if strings.Contains(charClassesStr.String, "numbers") {
				requiredCharClasses = append(requiredCharClasses, "numbers")
			}
			if strings.Contains(charClassesStr.String, "special_chars") {
				requiredCharClasses = append(requiredCharClasses, "special_chars")
			}
		}
	}

	return minLength, requiredCharClasses, nil
}

// ValidatePassword checks if a password meets the complexity requirements
func (p *PostgreSQL) ValidatePassword(ctx context.Context, password string) error {
	minLength, requiredCharClasses, err := p.GetPasswordSettings(ctx)
	if err != nil {
		return fmt.Errorf("failed to get password settings: %w", err)
	}

	// Check minimum length
	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters long", minLength)
	}

	// Check required character classes
	for _, charClass := range requiredCharClasses {
		switch charClass {
		case "lowercase":
			if !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
				return fmt.Errorf("password must contain at least one lowercase letter")
			}
		case "uppercase":
			if !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				return fmt.Errorf("password must contain at least one uppercase letter")
			}
		case "numbers":
			if !strings.ContainsAny(password, "0123456789") {
				return fmt.Errorf("password must contain at least one number")
			}
		case "special_chars":
			if !strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?") {
				return fmt.Errorf("password must contain at least one special character")
			}
		}
	}

	return nil
}

// generateSalt generates a 128-bit random salt as hex string (32 chars)
func (p *PostgreSQL) generateSalt() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback if crypto/rand fails
		return fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))[:32]
	}
	return fmt.Sprintf("%x", bytes)
}

// generateRandomString generates a cryptographically secure random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)

	// Use crypto/rand for secure random generation
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Fallback to time-based generation if crypto/rand fails
		for i := range b {
			b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		}
		return string(b)
	}

	for i := range b {
		b[i] = charset[randomBytes[i]%byte(len(charset))]
	}
	return string(b)
}

// IssueStatus represents a status from the issue_statuses table
type IssueStatus struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	IsClosed bool   `json:"is_closed"`
}

// GetAllowedStatusesForIssue retrieves the list of allowed status transitions for a given issue
// This works for both OSS Redmine and EasyRedmine as they share the same workflow table structure
func (p *PostgreSQL) GetAllowedStatusesForIssue(ctx context.Context, issueID int, userID int) ([]IssueStatus, error) {
	// First, get the issue details (current status, tracker, project)
	var currentStatusID, trackerID, projectID int
	issueQuery := `
		SELECT status_id, tracker_id, project_id
		FROM issues
		WHERE id = $1
	`
	err := p.db.QueryRowContext(ctx, issueQuery, issueID).Scan(&currentStatusID, &trackerID, &projectID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("issue not found")
		}
		return nil, fmt.Errorf("failed to get issue details: %w", err)
	}

	// Get user's roles in the project
	rolesQuery := `
		SELECT DISTINCT mr.role_id
		FROM members m
		INNER JOIN member_roles mr ON m.id = mr.member_id
		WHERE m.user_id = $1 AND m.project_id = $2
		UNION
		SELECT DISTINCT mr.role_id
		FROM members m
		INNER JOIN member_roles mr ON m.id = mr.member_id
		INNER JOIN groups_users gu ON m.user_id = gu.group_id
		WHERE gu.user_id = $1 AND m.project_id = $2
	`
	rows, err := p.db.QueryContext(ctx, rolesQuery, userID, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	roleIDs := []int{}
	for rows.Next() {
		var roleID int
		if err := rows.Scan(&roleID); err != nil {
			return nil, fmt.Errorf("failed to scan role ID: %w", err)
		}
		roleIDs = append(roleIDs, roleID)
	}

	if len(roleIDs) == 0 {
		// User has no roles in this project, return empty list
		return []IssueStatus{}, nil
	}

	// Get allowed status transitions from workflows table
	// The workflow table defines transitions from old_status_id to new_status_id
	// for a given tracker_id and role_id
	statusQuery := `
		SELECT DISTINCT s.id, s.name, s.is_closed
		FROM issue_statuses s
		INNER JOIN workflows w ON s.id = w.new_status_id
		WHERE w.tracker_id = $1
		  AND w.old_status_id = $2
		  AND w.role_id = ANY($3)
		ORDER BY s.id
	`

	statusRows, err := p.db.QueryContext(ctx, statusQuery, trackerID, currentStatusID, pq.Array(roleIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to query allowed statuses: %w", err)
	}
	defer statusRows.Close()

	statuses := []IssueStatus{}
	for statusRows.Next() {
		var status IssueStatus
		if err := statusRows.Scan(&status.ID, &status.Name, &status.IsClosed); err != nil {
			return nil, fmt.Errorf("failed to scan status: %w", err)
		}
		statuses = append(statuses, status)
	}

	return statuses, nil
}
