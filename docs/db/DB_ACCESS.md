# Database Access Documentation

This document outlines all database operations performed by the redmine-gateway application, organized by table and operation type.

## Tables and Operations

### users Table

#### Read Operations
- **AuthenticateUser** (internal/database/postgres.go:89)
  - **Data**: id, login, firstname, lastname, hashed_password, salt, status, created_on, updated_on, twofa_scheme, twofa_totp_key, twofa_totp_last_used_at, twofa_required, api_key (from tokens table)
  - **Why**: Authenticate user credentials against Redmine database
  - **Process**: User login authentication

- **GetUserByID** (internal/database/postgres.go:147)
  - **Data**: id, login, firstname, lastname, mail (from email_addresses), status, created_on, updated_on, api_key (from tokens)
  - **Why**: Retrieve complete user information by ID
  - **Process**: API proxy setup, user data retrieval

- **GetUserTwoFactorData** (internal/database/twofa.go:17)
  - **Data**: twofa_scheme, twofa_totp_key, twofa_totp_last_used_at, twofa_required, backup_codes_count (from tokens)
  - **Why**: Get 2FA configuration and status for user
  - **Process**: 2FA verification, enrollment, and management

- **HasTwoFactorEnabled** (internal/database/twofa.go:48)
  - **Data**: twofa_scheme
  - **Why**: Check if user has 2FA enabled
  - **Process**: Authentication flow decision making

- **IsTwoFactorRequired** (internal/database/twofa.go:58)
  - **Data**: twofa_scheme
  - **Why**: Check if 2FA is required (backward compatibility)
  - **Process**: Authentication flow

#### Write Operations
- **UpdateTOTPLastUsed** (internal/database/twofa.go:32)
  - **Data**: twofa_totp_last_used_at (timestamp)
  - **Why**: Update timestamp of last TOTP usage
  - **Process**: Successful TOTP verification

- **EnableTwoFactor** (internal/database/twofa.go:118)
  - **Data**: twofa_scheme='totp', twofa_totp_key (encrypted or plaintext base32), twofa_totp_last_used_at=NULL
  - **Why**: Enable TOTP 2FA for user
  - **Process**: 2FA enrollment completion

- **DisableTwoFactor** (internal/database/twofa.go:127)
  - **Data**: twofa_scheme=NULL, twofa_totp_key=NULL, twofa_totp_last_used_at=NULL
  - **Why**: Disable 2FA for user
  - **Process**: 2FA management

### tokens Table

#### Read Operations
- **AuthenticateUser** (internal/database/postgres.go:89)
  - **Data**: api_key value for user
  - **Why**: Get existing API key during authentication
  - **Process**: User login

- **GetUserTwoFactorData** (internal/database/twofa.go:17)
  - **Data**: count of twofa_backup_code actions
  - **Why**: Count remaining backup codes
  - **Process**: 2FA status checking

#### Write Operations
- **GenerateAPIKey** (internal/database/postgres.go:119)
  - **Data**: user_id, action='api', value (40-char key), created_on, updated_on
  - **Why**: Store new API key for user
  - **Process**: API key generation

- **GenerateBackupCodes** (internal/database/twofa.go:67)
  - **Data**: user_id, action='twofa_backup_code', value (8-char code), created_on
  - **Why**: Store backup codes for 2FA
  - **Process**: 2FA enrollment

#### Delete Operations
- **GenerateAPIKey** (internal/database/postgres.go:114)
  - **Data**: existing api tokens for user
  - **Why**: Remove old API tokens before generating new one
  - **Process**: API key regeneration

- **GenerateBackupCodes** (internal/database/twofa.go:63)
  - **Data**: existing twofa_backup_code tokens for user
  - **Why**: Remove old backup codes before generating new ones
  - **Process**: Backup code regeneration

- **ValidateAndConsumeBackupCode** (internal/database/twofa.go:89)
  - **Data**: specific backup code token
  - **Why**: Consume (delete) used backup code
  - **Process**: Backup code verification

- **DisableTwoFactor** (internal/database/twofa.go:135)
  - **Data**: twofa_backup_code tokens for user
  - **Why**: Remove backup codes when disabling 2FA
  - **Process**: 2FA disable

### projects Table

#### Read Operations
- **GetUserProjects** (internal/database/postgres.go:175)
  - **Data**: id, name, identifier, description, status
  - **Why**: Get projects accessible to user
  - **Process**: Project listing for user

### members Table

#### Read Operations
- **GetUserProjects** (internal/database/postgres.go:175)
  - **Data**: project_id for user's memberships
  - **Why**: Filter projects by user membership
  - **Process**: Project access control

### issues Table

#### Read Operations
- **GetUserIssues** (internal/database/postgres.go:195)
  - **Data**: id, subject, description, status_id, priority_id, project_id, tracker_id, author_id, assigned_to_id, created_on, updated_on, due_date
  - **Why**: Get issues accessible to user with filters
  - **Process**: Issue listing and management

- **GetIssueSubjects** (internal/database/postgres.go:245)
  - **Data**: id, subject for multiple issues
  - **Why**: Get issue subjects to enrich time entries
  - **Process**: Time entry enrichment

- **QueryTaskInvolvement** (internal/database/task_involvement_queries.go:21)
  - **Data**: id, subject, assigned_to_id, spent_time (aggregated), comment indicators, status change indicators
  - **Why**: Get tasks where user had involvement during period
  - **Process**: Weekly task involvement reporting

- **CountTaskInvolvement** (internal/database/task_involvement_queries.go:125)
  - **Data**: count of issues matching involvement criteria
  - **Why**: Get total count for pagination
  - **Process**: Task involvement pagination

### time_entries Table

#### Read Operations
- **QueryTaskInvolvement** (internal/database/task_involvement_queries.go:21)
  - **Data**: issue_id, user_id, hours, spent_on
  - **Why**: Calculate spent time and filter tasks with time entries
  - **Process**: Task involvement calculation

- **CountTaskInvolvement** (internal/database/task_involvement_queries.go:125)
  - **Data**: issue_id, user_id, spent_on
  - **Why**: Count tasks with time entries in period
  - **Process**: Task involvement counting

### journals Table

#### Read Operations
- **QueryTaskInvolvement** (internal/database/task_involvement_queries.go:21)
  - **Data**: journalized_id, journalized_type, user_id, notes, created_on
  - **Why**: Detect user comments and status changes
  - **Process**: Task involvement analysis

- **CountTaskInvolvement** (internal/database/task_involvement_queries.go:125)
  - **Data**: journalized_id, journalized_type, user_id, notes, created_on
  - **Why**: Count tasks with user activity
  - **Process**: Task involvement counting

### journal_details Table

#### Read Operations
- **QueryTaskInvolvement** (internal/database/task_involvement_queries.go:21)
  - **Data**: journal_id, property, prop_key, old_value
  - **Why**: Track status changes and assignment changes
  - **Process**: Task involvement analysis

- **CountTaskInvolvement** (internal/database/task_involvement_queries.go:125)
  - **Data**: journal_id, property, prop_key, old_value
  - **Why**: Count tasks with status/assignment changes
  - **Process**: Task involvement counting

### settings Table

#### Read Operations
- **checkRestAPIEnabled** (internal/redmine/redmine.go:308)
  - **Data**: rest_api_enabled setting value
  - **Why**: Check if Redmine REST API is enabled
  - **Process**: API proxy initialization

### email_addresses Table

#### Read Operations
- **GetUserByID** (internal/database/postgres.go:147)
  - **Data**: address for user's default email
  - **Why**: Get user's email address
  - **Process**: User profile retrieval

## Summary by Operation Type

### Read Operations (SELECT)
- User authentication and profile data
- 2FA configuration and status
- Project access permissions
- Issue listings and details
- Task involvement reporting
- API configuration checks

### Write Operations (INSERT/UPDATE)
- API key generation and storage
- 2FA configuration (enable/disable)
- Backup code generation
- TOTP usage tracking

### Delete Operations (DELETE)
- Old API token cleanup
- Used backup code consumption
- 2FA disable cleanup

## Security Considerations
- All database operations use parameterized queries to prevent SQL injection
- Password verification uses Redmine's custom hashing algorithm
- 2FA secrets are encrypted using AES-256-CBC when REDMINE_SECRET_KEY_BASE is configured, otherwise stored as plaintext base32 (matching Redmine 6.x behavior)
- API keys and tokens are properly scoped and expired
- Backup codes are single-use and consumed upon validation