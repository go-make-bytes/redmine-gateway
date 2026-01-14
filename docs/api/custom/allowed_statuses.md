# Get Allowed Statuses

## Overview

This endpoint returns the allowed status transitions for a specific issue/task. The query takes into account the user's role and the workflow transition definitions configured in Redmine.

## Request

```http
GET /api/issues/allowed_statuses?issue_id={issue_id}
```

`issue_id` - The ID of the issue for which to retrieve allowed status transitions

### Authorization

Requires a valid OAuth access token in the Authorization header (Bearer token)

### Example

```bash
curl -X GET "http://localhost:8080/api/issues/allowed_statuses?issue_id=123" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Response

JSON object containing the list of allowed statuses:

```json
{
    "allowed_statuses": [
        {
            "id": int,
            "name": string,
            "is_closed": boolean
        }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `allowed_statuses` | array | List of status objects that the issue can transition to |
| `id` | int | Unique identifier of the status |
| `name` | string | Display name of the status |
| `is_closed` | boolean | Whether this status marks the issue as closed |

### Example Response

```json
{
    "allowed_statuses": [
        {
            "id": 3,
            "name": "In Process",
            "is_closed": false
        },
        {
            "id": 4,
            "name": "Solved",
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