# Redmine Gateway Service's Relationship with the Redmine Database

> [!Warning]
> Only PostgreSQL server is supported

## Operations directly on the database

All operations done directly in Redmine database are described in [DB access document](DB_ACCESS.md)

## Database User

It is highly recommended that you create a specific user for the `Redmine Gateway` service, with only the needed permissions.

The user can be created using the [provided script](create_redmine_gateway_user.sql)

> [!Warning]
> Change `your_secure_password` to a generated, secure password