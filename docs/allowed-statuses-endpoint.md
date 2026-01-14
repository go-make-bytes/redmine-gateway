# Allowed Statuses Endpoint

## Overview
This document describes the new endpoint `GET /api/issues/allowed_statuses` that provides workflow-based status transitions for issues in both OSS Redmine and EasyRedmine.

## Problem Statement
EasyRedmine dropped the `include=allowed_statuses` feature that was available in OSS Redmine's API endpoint `GET /issues/{issue_id}.json?include=allowed_statuses`. This new endpoint provides a unified solution that works for both platforms by querying the database directly.

## Implementation

### 1. Database Layer (`internal/database/postgres.go`)

Added `GetAllowedStatusesForIssue` function that:
- Retrieves the issue's current status, tracker, and project from the `issues` table
- Queries the user's roles in the project (including roles through group membership)
- Queries the `workflows` table to find allowed status transitions based on:
  - Current status (`old_status_id`)
  - Tracker type (`tracker_id`)
  - User's role(s) (`role_id`)
- Returns a list of allowed statuses with their IDs, names, and closed status

**Key SQL Tables Used:**
- `issues` - to get current issue state
- `members` - to get user's project roles
- `groups_users` - to handle group-based role assignments
- `workflows` - to determine allowed status transitions
- `issue_statuses` - to get status details

### 2. Handler Layer (`internal/redmine/issues.go`)

Added `GetAllowedStatusesForIssue` handler that:
- Validates user authentication
- Extracts and validates the `issue_id` query parameter
- Calls the database function to retrieve allowed statuses
- Returns a JSON response with the allowed statuses

### 3. Router Configuration (`cmd/server/main.go`)

Registered the new endpoint in the API router:
```go
api.GET("/issues/allowed_statuses", redmineHandler.GetAllowedStatusesForIssue)
```

**Important:** The endpoint is placed before the `api.GET("/issues/:id", ...)` route to ensure it's matched correctly.

## API Usage

### Endpoint
```
GET /api/issues/allowed_statuses?issue_id={issue_id}
```

### Authentication
Requires a valid OAuth access token in the Authorization header:
```
Authorization: Bearer {access_token}
```

### Request Parameters
- `issue_id` (required): The ID of the issue to query

### Response Format

**Success Response (200 OK):**
```json
{
  "allowed_statuses": [
    {
      "id": 2,
      "name": "In Progress",
      "is_closed": false
    },
    {
      "id": 5,
      "name": "Closed",
      "is_closed": true
    }
  ]
}
```

**Error Responses:**

*Missing issue_id (400 Bad Request):*
```json
{
  "error": "Missing required parameter",
  "description": "issue_id parameter is required"
}
```

*Invalid issue_id (400 Bad Request):*
```json
{
  "error": "Invalid issue_id",
  "description": "issue_id must be a valid integer"
}
```

*Issue not found (404 Not Found):*
```json
{
  "error": "Issue not found",
  "description": "The specified issue does not exist"
}
```

*Unauthorized (401):*
```json
{
  "error": "User not authenticated"
}
```

*Server error (500):*
```json
{
  "error": "Failed to retrieve allowed statuses",
  "description": "An error occurred while querying allowed status transitions"
}
```

## Platform Compatibility

This endpoint works identically on both:
- **OSS Redmine** - Uses standard Redmine database schema
- **EasyRedmine** - Uses the same workflow tables as OSS Redmine

The workflow logic is based on the standard Redmine database schema which EasyRedmine preserves.

## Example Usage

### Using cURL
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  "http://localhost:8080/api/issues/allowed_statuses?issue_id=123"
```

### Using JavaScript (Fetch API)
```javascript
const response = await fetch(
  'http://localhost:8080/api/issues/allowed_statuses?issue_id=123',
  {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  }
);
const data = await response.json();
console.log(data.allowed_statuses);
```

## Database Schema Reference

The endpoint relies on the following Redmine database tables:

### workflows
- `tracker_id` - The tracker type (Bug, Feature, etc.)
- `old_status_id` - Current status of the issue
- `new_status_id` - Status that the issue can transition to
- `role_id` - Role that is allowed to make this transition

### issue_statuses
- `id` - Status ID
- `name` - Status name (e.g., "New", "In Progress", "Closed")
- `is_closed` - Boolean indicating if this status closes the issue

### issues
- `id` - Issue ID
- `status_id` - Current status
- `tracker_id` - Tracker type
- `project_id` - Project the issue belongs to

### members
- `user_id` - User or group ID
- `project_id` - Project ID
- `role_id` - Role assigned

### groups_users
- `group_id` - Group ID
- `user_id` - User who is member of the group

## Security Considerations

1. **Authentication Required**: The endpoint requires a valid OAuth token
2. **User Permissions**: Only shows transitions allowed for the user's role(s) in the project
3. **Project Membership**: Returns empty list if user has no roles in the issue's project
4. **Input Validation**: Validates issue_id parameter to prevent SQL injection

## Testing Recommendations

1. Test with a user who has multiple roles in a project
2. Test with a user who is member of a group with project access
3. Test with different trackers (Bug, Feature, Task, etc.)
4. Test with issues in different statuses
5. Test with non-existent issue IDs
6. Test with users who have no access to the issue's project
7. Verify behavior is consistent between OSS Redmine and EasyRedmine installations
