# Get Assignable Users

## Overview

This endpoint returns the list of users and groups that can be assigned to issues within a specific project. The list takes into account project membership and user permissions.

## Request

```http
GET /api/projects/{project_id}/assignable_users
```

`project_id` - The ID of the project for which to retrieve assignable users

### Authorization

Requires a valid OAuth access token in the Authorization header (Bearer token)

### Example

```bash
curl -X GET "http://localhost:8080/api/projects/123/assignable_users" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Response

JSON array containing the list of assignable users and groups:

```json
[
    {
        "id": int,
        "name": "string",
        "type": "string"
    }
]
```

| Property | Type | Description |
|----------|------|-------------|
| `id` | int | Unique identifier of the user or group |
| `name` | string | Full name of the user (first and last name) or group name |
| `type` | string | Type of entity: `User` or `Group` |

### Example Response

```json
[
    {
        "id": 1,
        "name": "John Doe",
        "type": "User"
    },
    {
        "id": 123,
        "name": "Developers",
        "type": "Group"
    }
]
```