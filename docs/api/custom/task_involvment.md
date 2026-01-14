# Get Task Involvement

## Overview

Returns a list of issues in which the user was possibly involved this week.

> [!Warning]
> At this moment, the endpoint is hardcoded to return the current week, not the last 7 days.

What issues the endpoint returns and why they are considered "possibly involved":

1. Issues WHERE the user was assignee AND the assignee was changed (Didn't find how to filter this data)

    > Assumption: that the user did the task but it was returned to the author, for example, and they forgot to change status or fill spent time.

2. Issues WHERE the user is STILL the assignee, BUT the issue status was changed

    > Assumption: that the user did the task, or part of it, but forgot to fill spent time.

3. User added a comment to ANY task

    > It clearly shows that the user was involved in this task

4. User logged spent time

    > It clearly shows that the user was involved in this task

The user can review these tasks and fill in spent time where they forgot to do it.

## Request

```http
GET /api/reports/task-involvement
```

### Authorization

Requires a valid OAuth access token in the Authorization header (Bearer token)

### Example

```bash
curl -X GET "http://localhost:8080/api/reports/task-involvement" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Response

JSON object containing the list of tasks where the user possibly was involved and metadata:

```json
{
    "data": [
        {
            "task_id": int,
            "subject": "string",
            "spent_time": number,
            "have_my_comment": int,
            "status_changed": int,
            "still_assignee": int
        }
    ],
    "metadata": {
        "total_count": int,
        "from_date": "string",
        "to_date": "string",
        "generated_at": "string",
        "has_next": boolean,
        "has_prev": boolean,
        "limit": int,
        "offset": int
    }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `data` | array | Array of task involvement records |
| `data[].task_id` | int | Unique identifier of the issue/task |
| `data[].subject` | string | Subject/title of the issue |
| `data[].spent_time` | number | Hours spent on the task (can be decimal, e.g., 1.5) |
| `data[].have_my_comment` | int | Whether the user has commented on this task (0 = no, 1 = yes) |
| `data[].status_changed` | int | Whether the user changed the status of this task (0 = no, 1 = yes) |
| `data[].still_assignee` | int | Whether the user is still assigned to this task (0 = no, 1 = yes) |
| `metadata` | object | Pagination and report metadata |
| `metadata.total_count` | int | Total number of tasks in the report |
| `metadata.from_date` | string | Start date of the report period (YYYY-MM-DD) |
| `metadata.to_date` | string | End date of the report period (YYYY-MM-DD) |
| `metadata.generated_at` | string | Timestamp when the report was generated (ISO 8601) |
| `metadata.has_next` | boolean | Whether there are more results after the current page |
| `metadata.has_prev` | boolean | Whether there are results before the current page |
| `metadata.limit` | int | Maximum number of results per page |
| `metadata.offset` | int | Number of results skipped (for pagination) |

### Example Response

```json
{
    "data": [
        {
            "task_id": 123,
            "subject": "Create new endpoint",
            "spent_time": 0,
            "have_my_comment": 1,
            "status_changed": 1,
            "still_assignee": 1
        },
        {
            "task_id": 124,
            "subject": "Test endpoint",
            "spent_time": 1.5,
            "have_my_comment": 0,
            "status_changed": 1,
            "still_assignee": 0
        }
    ],
    "metadata": {
        "total_count": 2,
        "from_date": "2026-01-12",
        "to_date": "2026-01-18",
        "generated_at": "2026-01-14T09:08:53.915180564+02:00",
        "has_next": false,
        "has_prev": false,
        "limit": 1000,
        "offset": 0
    }
}
```