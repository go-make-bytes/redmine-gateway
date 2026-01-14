# Database Access Documentation

This document outlines all database operations performed by the redmine-gateway application, organized by table and operation type.

## Tables and Operations

### users Table

#### Read Operations
- **AuthenticateUser** (internal/database/postgres.go:110)
  - **Data**: id, login, firstname, lastname, hashed_password, salt, status, created_on, updated_on, must_change_passwd, api_key (from tokens table)
  - **Why**: Authenticate user credentials against Redmine database (case-insensitive login lookup)
  - **Process**: User login authentication

- **GetUserByID** (internal/database/postgres.go:147)
  - **Data**: id, login, firstname, lastname, mail (from email_addresses), status, created_on, updated_on, must_change_passwd, api_key (from tokens)
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

- **FindUserByLoginAndAuthSource** (internal/database/ldap.go:71)
  - **Data**: id, login, firstname, lastname, auth_source_id, status
  - **Why**: Find existing LDAP user by login and auth source (case-insensitive lookup)
  - **Process**: LDAP authentication, duplicate prevention

#### Write Operations
- **CreateLDAPUser** (internal/database/ldap.go:95)
  - **Data**: login, firstname, lastname, auth_source_id, status=1, type='User', created_on, updated_on
  - **Why**: Create new user from LDAP authentication
  - **Process**: LDAP user provisioning

- **UpdateLDAPUserAttributes** (internal/database/ldap.go:131)
  - **Data**: firstname, lastname, updated_on
  - **Why**: Synchronize user attributes from LDAP
  - **Process**: LDAP attribute sync during login
- **UpdateTOTPLastUsed** (internal/database/twofa.go:32)
  - **Data**: twofa_totp_last_used_at (timestamp)
  - **Why**: Update timestamp of last TOTP usage
  - **Process**: Successful TOTP verification

- **EnableTwoFactor** (internal/database/twofa.go:118)
  - **Data**: Platform-aware - OSS Redmine: twofa_scheme='totp', twofa_totp_key; EasyRedmine: delegates to EnableEasyTwoFactor
  - **Why**: Enable TOTP 2FA for user
  - **Process**: 2FA enrollment completion

- **DisableTwoFactor** (internal/database/twofa.go:127)
  - **Data**: twofa_scheme=NULL, twofa_totp_key=NULL, twofa_totp_last_used_at=NULL
  - **Why**: Disable 2FA for user
  - **Process**: 2FA management

- **ChangePassword** (internal/database/postgres.go:267)
  - **Data**: hashed_password, salt, passwd_changed_on (timestamp), must_change_passwd=false
  - **Why**: Update user's password using Redmine's hashing algorithm and clear password change requirement
  - **Process**: Password change functionality

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

- **ChangePassword** (internal/database/postgres.go:267)
  - **Data**: recovery, autologin, and session tokens for user
  - **Why**: Delete security-sensitive tokens after password change (Redmine security practice)
  - **Process**: Password change security cleanup

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

- **GetAssignableUsers** (internal/database/postgres.go:102)
  - **Data**: user_id, project_id
  - **Why**: Find users who are members of a project
  - **Process**: Assignable user lookup for issues

- **GetAllowedStatusesForIssue** (internal/database/postgres.go:620)
  - **Data**: id (member_id), user_id, project_id
  - **Why**: Find user's direct project memberships for workflow permissions
  - **Process**: Status transition authorization

### member_roles Table

#### Read Operations
- **GetAssignableUsers** (internal/database/postgres.go:102)
  - **Data**: member_id, role_id
  - **Why**: Link members to their roles in projects
  - **Process**: Role-based access control for assignments

- **GetAllowedStatusesForIssue** (internal/database/postgres.go:620)
  - **Data**: member_id, role_id
  - **Why**: Get user's role(s) in project (many-to-many relationship)
  - **Process**: Workflow-based status transition permissions

### groups_users Table

#### Read Operations
- **GetAllowedStatusesForIssue** (internal/database/postgres.go:620)
  - **Data**: group_id, user_id
  - **Why**: Get roles inherited through group membership
  - **Process**: Group-based workflow permissions

### workflows Table

#### Read Operations
- **GetAllowedStatusesForIssue** (internal/database/postgres.go:620)
  - **Data**: tracker_id, old_status_id, new_status_id, role_id
  - **Why**: Determine allowed status transitions based on tracker, current status, and user's role(s)
  - **Process**: Workflow-based status change authorization

### issue_statuses Table

#### Read Operations
- **GetAllowedStatusesForIssue** (internal/database/postgres.go:620)
  - **Data**: id, name, is_closed
  - **Why**: Get details of allowed target statuses for display
  - **Process**: Status transition UI population

### roles Table

#### Read Operations
- **GetAssignableUsers** (internal/database/postgres.go:102)
  - **Data**: id, assignable (boolean flag)
  - **Why**: Check if a role allows issue assignment
  - **Process**: Filter users who can be assigned to issues

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

- **GetPasswordSettings** (internal/database/postgres.go:295)
  - **Data**: password_min_length, password_required_char_classes
  - **Why**: Retrieve password complexity requirements from Redmine settings
  - **Process**: Password validation during change

## Summary by Operation Type

### Read Operations (SELECT)
- User authentication and profile data (case-insensitive login)
- LDAP source configuration and user lookup
- 2FA configuration and status (platform-aware)
- Project access permissions
- Issue listings and details
- Workflow-based status transitions (role and tracker aware)
- Task involvement reporting
- API configuration checks
- EasyRedmine 2FA schemes (when applicable)

### Write Operations (INSERT/UPDATE)
- LDAP user creation and attribute synchronization
- Email address provisioning for LDAP users
- API key generation and storage
- 2FA configuration (enable/disable, platform-aware)
- EasyRedmine 2FA scheme management
- Backup code generation
- TOTP usage tracking
- Password updates and security token cleanup

### Delete Operations (DELETE)
- Old API token cleanup
- Used backup code consumption
- 2FA disable cleanup
- Security token cleanup after password changes

## Security Considerations
- All database operations use parameterized queries to prevent SQL injection
- **Case-insensitive login matching** prevents duplicate users with different cases (e.g., `gatisb` vs `GatisB`)
- Password verification uses Redmine's custom hashing algorithm (SHA1 with salt)
- 2FA secrets are encrypted using AES-256-CBC when REDMINE_SECRET_KEY_BASE is configured, otherwise stored as plaintext base32 (matching Redmine 6.x behavior)
- LDAP passwords are never stored in the database
- LDAP attribute retrieval uses case-insensitive matching (e.g., `sAMAccountName` vs `samaccountname`)
- API keys and tokens are properly scoped and expired
- Backup codes are single-use and consumed upon validation
- Platform detection ensures correct table usage (OSS vs EasyRedmine)

### email_addresses Table

#### Read Operations
- **GetUserByID** (internal/database/postgres.go:147)
  - **Data**: address for user's default email
  - **Why**: Get user's email address
  - **Process**: User profile retrieval

#### Write Operations
- **CreateLDAPUser** (internal/database/ldap.go:95)
  - **Data**: user_id, address (email), is_default=true, notify=true, created_on, updated_on
  - **Why**: Store email address for newly created LDAP user
  - **Process**: LDAP user provisioning

- **UpdateLDAPUserAttributes** (internal/database/ldap.go:131)
  - **Data**: address (email), updated_on
  - **Why**: Update email address from LDAP during login
  - **Process**: LDAP attribute sync

### auth_sources Table

#### Read Operations
- **GetLDAPSources** (internal/database/ldap.go:46)
  - **Data**: id, type, name, host, port, base_dn, attr_login, attr_firstname, attr_lastname, attr_mail, account, account_password, onthefly_register, tls, filter
  - **Why**: Get all configured LDAP servers for authentication
  - **Process**: LDAP authentication flow

### easy_twofa_user_schemes Table (EasyRedmine Only)

#### Read Operations
- **GetEasyTwofaScheme** (internal/database/twofa_easy.go:19)
  - **Data**: id, user_id, scheme_type, active, settings (JSON with totp_key and last_used_at)
  - **Why**: Get EasyRedmine 2FA configuration
  - **Process**: Platform-aware 2FA retrieval

#### Write Operations
- **EnableEasyTwoFactor** (internal/database/twofa_easy.go:45)
  - **Data**: user_id, scheme_type='totp', active=true, settings (JSON with totp_key and last_used_at)
  - **Why**: Enable TOTP 2FA in EasyRedmine format
  - **Process**: EasyRedmine 2FA enrollment

- **UpdateEasyTOTPLastUsed** (internal/database/twofa_easy.go:105)
  - **Data**: settings (JSON updated with new last_used_at timestamp)
  - **Why**: Track TOTP usage in EasyRedmine
  - **Process**: TOTP verification

## Platform Detection

The application automatically detects whether it's running against OSS Redmine or EasyRedmine by checking for:
- **easy_twofa_user_schemes** table existence (EasyRedmine 2FA)
- **easy_page_modules** table existence (EasyRedmine modules)

Based on detection, it adapts:
- **2FA operations**: Uses `users.twofa_*` columns for OSS Redmine, `easy_twofa_user_schemes` table for EasyRedmine
- **User lookup**: Case-insensitive login matching for both platforms

### settings Table

#### Read Operations
- **checkRestAPIEnabled** (internal/redmine/redmine.go:308)