# Custom Redmine Gateway api endpoints

Since redmine do not provide some functionality via API, custom API endpoints are created. Calling those endpoints `redmine-gateway` will query Redmine database (PostgreSQL is supported) and provide response.

## Endpoints 


### Get time entries with issue subjects included

The enriched time entries endpoint enhances Redmine's standard time entries API by adding issue subjects directly to each time entry. This solves a common problem where the standard Redmine API only returns issue IDs without their corresponding subjects, making it difficult for users to understand what work was done without additional API calls.

API method [description](./enriched_time.md)

### Get allowed statuses

This endpoint returns the allowed status transitions for a specific issue/task. The query takes into account the user's role and the workflow transition definitions configured in Redmine.

API method [description](./allowed_statuses.md)

### Get assignable users

This endpoint returns the list of users and groups that can be assigned to issues within a specific project. The list takes into account project membership and user permissions.

API method [description](./assignable_users.md)


### Get Issues and witch user was (possible) working this week

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

API method [description](./task_involvment.md)