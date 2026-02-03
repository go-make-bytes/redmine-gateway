# Redmine API Gateway Usage

This service acts as a secure gateway for the Redmine REST API, providing authentication and authorization on top of Redmine's native API. It proxies authenticated requests to the Redmine server, ensuring that users can only access data they are authorized for through their Redmine API keys.

## How the Service Works

1. **Authentication**: All API requests must include a valid OAuth access token obtained through the `/oauth/token` endpoint. The service supports OAuth 2.0 flows for user authentication.

2. **Authorization**: Upon successful authentication, the service retrieves the user's Redmine API key from the database and uses it to authenticate requests to the Redmine server.

3. **Proxying**: The gateway forwards requests to the corresponding Redmine API endpoints, automatically appending `.json` to the URL for JSON responses. It handles request headers, query parameters, and response data transparently.

4. **Security Features**: The service includes rate limiting, CORS protection, CSRF protection, and two-factor authentication (2FA) support for enhanced security.

## Proxy Logic

Redmine API calls through this gateway should be made without the `.json` suffix. The service automatically appends `.json` to ensure JSON responses from Redmine.

The Redmine REST API is fully documented at [Redmine official webpage](https://www.redmine.org/projects/redmine/wiki/Rest_api).

## API Endpoints

The gateway supports the following Redmine API endpoints:

- Projects (`/api/projects`)
- Issues (`/api/issues`)
- Users (`/api/users`)
- Time Entries (`/api/time_entries`)
- Uploads and Attachments (`/api/uploads`, `/api/attachments`)
- Enumerations and Metadata (`/api/trackers`, `/api/issue_statuses`, etc.)

## Call Examples

| Gateway Endpoint | Proxied Redmine Endpoint | Description |
|---|---|---|
| `GET /api/user` | `GET /users/current.json` | Get current authenticated user information |
| `GET /api/projects` | `GET /projects.json` | List all accessible projects |
| `GET /api/projects/{project_id}` | `GET /projects/{project_id}.json` | Get specific project details |
| `GET /api/projects/{project_id}?include=time_entry_activities` | `GET /projects/{project_id}.json?include=time_entry_activities` | Get project data with time entry activities |
| `GET /api/projects/{project_id}/memberships` | `GET /projects/{project_id}/memberships.json` | Get project members and their roles |
| `GET /api/projects/{project_id}/assignable_users` | `GET /projects/{project_id}/assignable_users.json` | Get users who can be assigned to project issues |
| `GET /api/issues` | `GET /issues.json` | List all accessible issues with optional filters |
| `GET /api/issues?set_filter=1&assigned_to_id=me&status_id=o` | `GET /issues.json?set_filter=1&assigned_to_id=me&status_id=o` | Get issues assigned to current user with open status |
| `GET /api/issues/{issue_id}` | `GET /issues/{issue_id}.json` | Get specific issue details |
| `GET /api/issues/{issue_id}?include=journals` | `GET /issues/{issue_id}.json?include=journals` | Get issue details with journals (comments and history) |
| `POST /api/issues` | `POST /issues.json` | Create a new issue with project, tracker, subject, etc. |
| `PUT /api/issues/{issue_id}` | `PUT /issues/{issue_id}.json` | Update an existing issue (status, assignee, subject, etc.) |
| `PUT /api/issues/{issue_id}` with notes | `PUT /issues/{issue_id}.json` | Add a comment to an issue (using `notes` field in payload) |
| `GET /api/issues/allowed_statuses?issue_id={issue_id}` | `GET /issues/allowed_statuses.json?issue_id={issue_id}` | Get allowed status transitions for a specific issue |
| `GET /api/trackers` | `GET /trackers.json` | List all available issue trackers (bug, feature, task, etc.) |
| `GET /api/issue_statuses` | `GET /issue_statuses.json` | List all issue statuses (new, in progress, closed, etc.) |
| `GET /api/enumerations/issue_priorities` | `GET /enumerations/issue_priorities.json` | List issue priorities (low, normal, high, urgent, immediate) |
| `POST /api/uploads?filename={filename}` | `POST /uploads.json?filename={filename}` | Upload a file attachment (returns upload token for use in issues) |
| `GET /api/time_entries?spent_on=current_month&user_id=me` | `GET /time_entries.json?spent_on=current_month&user_id=me` | Get time entries for current user in current month |
| `GET /api/time_entries/enriched?spent_on=current_month&user_id=me` | `GET /time_entries/enriched.json?spent_on=current_month&user_id=me` | Get time entries with enriched project and issue data |
| `GET /api/time_entries/{time_entry_id}.json` | `GET /time_entries/{time_entry_id}.json` | Get specific time entry details |
| `POST /api/time_entries` | `POST /time_entries.json` | Create a new time entry with project, issue, hours, and date |
| `PUT /api/time_entries/{time_entry_id}` | `PUT /time_entries/{time_entry_id}.json` | Update an existing time entry |
| `GET /api/reports/task-involvement` | `GET /reports/task-involvement.json` | Get task involvement report for current user |


## Specific call examples


### Get overdue issues assigned to current user, sorted by due date and priority

```
GET /api/issues?set_filter=1&f[]=status_id&f[]=assigned_to_id&f[]=due_date&op[status_id]=o&op[assigned_to_id]=%3D&v[assigned_to_id][]=me&op[due_date]=%3E%3Ct%2B&v[due_date][]=7&sort=priority:desc,updated_on:desc
```

### Get upcoming issues (due in next 7 days) assigned to current user

```
GET /api/issues?set_filter=1&f[]=status_id&f[]=assigned_to_id&f[]=due_date&op[status_id]=o&op[assigned_to_id]=%3D&v[assigned_to_id][]=me&op[due_date]=%3E%3Ct%2B&v[due_date][]=7&sort=priority:desc,updated_on:desc
```


## Authentication Example

To use the API, first obtain an access token

Then use the token in API requests:

```bash
curl -X GET http://localhost:8080/api/issues/111131 \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Error Handling

The gateway returns standard HTTP status codes and JSON error responses. Common errors include:
- `401 Unauthorized`: Invalid or missing access token
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Gateway or Redmine server error

## Rate Limiting

The service implements rate limiting to prevent abuse. Exceeding limits will result in `429 Too Many Requests` responses.