# Redmine Gateway service relation with Redmine database

> [!Warning]
> Only PostgreSQL server is supported

## Operations directly in database

All operations done directly in Redmine database is described in [DB access document](DB_ACCESS.md)

## DB user

It is highty recomended, that you create a specific user for `Redmine Gateway` service, with only needed permitions. 

User can be created [using script](create_redmine_gateway_user.sql)

> [!Warning]
> Change `your_secure_password` to generated and secure password