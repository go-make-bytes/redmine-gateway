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
| `GET /api/issues/{issue_id}?include=journals` | `GET /issues/{issue_id}.json?include=journals` | Get issue details with journals |
| `GET /api/projects/{project_id}?include=time_entry_activities` | `GET /projects/{project_id}.json?include=time_entry_activities` | Get project data with time entry activities |
| `GET /api/issues?project_id={project_id}&status_id=open` | `GET /issues.json?project_id={project_id}&status_id=open` | List issues for a project with open status |
| `POST /api/issues` | `POST /issues.json` | Create a new issue |
| `PUT /api/issues/{issue_id}` | `PUT /issues/{issue_id}.json` | Update an existing issue |
| `GET /api/projects` | `GET /projects.json` | List all accessible projects |
| `GET /api/projects/{project_id}/memberships` | `GET /projects/{project_id}/memberships.json` | Get project memberships |
| `GET /api/users/current` | `GET /users/current.json` | Get current user information |
| `GET /api/time_entries?user_id={user_id}&from=2024-01-01&to=2024-01-31` | `GET /time_entries.json?user_id={user_id}&from=2024-01-01&to=2024-01-31` | Get time entries for a user in a date range |
| `POST /api/time_entries` | `POST /time_entries.json` | Create a new time entry |
| `GET /api/trackers` | `GET /trackers.json` | List available trackers |
| `GET /api/issue_statuses` | `GET /issue_statuses.json` | List issue statuses |
| `GET /api/enumerations/issue_priorities` | `GET /enumerations/issue_priorities.json` | List issue priorities |

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