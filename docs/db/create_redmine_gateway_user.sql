-- SQL Script to create PostgreSQL user 'redmine-gateway' with appropriate permissions
-- DEPRECATED: This file is kept for backward compatibility only
-- 
-- Please use the platform-specific scripts instead:
--   - create_redmine_gateway_user_oss.sql  for vanilla/OSS Redmine (v4.x - v6.x)
--   - create_redmine_gateway_user_easy.sql for EasyRedmine (all versions)
--
-- This generic script includes permissions for both platforms and may grant
-- unnecessary permissions or fail if platform-specific tables don't exist.

-- Create the user (replace 'your_secure_password' with a strong password)
CREATE USER "redmine-gateway" WITH PASSWORD 'your_secure_password';

-- Grant read-only access to all Redmine tables
GRANT SELECT ON users TO "redmine-gateway";
GRANT SELECT ON tokens TO "redmine-gateway";
GRANT SELECT ON projects TO "redmine-gateway";
GRANT SELECT ON members TO "redmine-gateway";
GRANT SELECT ON member_roles TO "redmine-gateway";
GRANT SELECT ON roles TO "redmine-gateway";
GRANT SELECT ON issues TO "redmine-gateway";
GRANT SELECT ON issue_statuses TO "redmine-gateway";
GRANT SELECT ON workflows TO "redmine-gateway";
GRANT SELECT ON groups_users TO "redmine-gateway";
GRANT SELECT ON time_entries TO "redmine-gateway";
GRANT SELECT ON journals TO "redmine-gateway";
GRANT SELECT ON journal_details TO "redmine-gateway";
GRANT SELECT ON settings TO "redmine-gateway";
GRANT SELECT ON email_addresses TO "redmine-gateway";
GRANT SELECT ON auth_sources TO "redmine-gateway";

-- EasyRedmine-specific tables (only needed if using EasyRedmine)
GRANT SELECT ON easy_twofa_user_schemes TO "redmine-gateway";

-- Grant write/delete permissions only on tables needed by the service
-- users table: UPDATE operations for 2FA settings and password changes
-- INSERT for LDAP user provisioning
GRANT UPDATE (twofa_scheme, twofa_totp_key, twofa_totp_last_used_at, hashed_password, salt, passwd_changed_on, must_change_passwd) ON users TO "redmine-gateway";
GRANT INSERT ON users TO "redmine-gateway";

-- email_addresses table: INSERT for LDAP user provisioning
GRANT INSERT ON email_addresses TO "redmine-gateway";

-- EasyRedmine-specific tables (only needed if using EasyRedmine)
GRANT INSERT, UPDATE ON easy_twofa_user_schemes TO "redmine-gateway";

-- tokens table: INSERT and DELETE operations for API keys, 2FA backup codes, and security token cleanup
GRANT INSERT, DELETE ON tokens TO "redmine-gateway";

-- Grant usage on sequences if needed for INSERT operations
-- (Note: Redmine typically uses auto-incrementing IDs, so sequence permissions may be needed)
GRANT USAGE, SELECT ON SEQUENCE tokens_id_seq TO "redmine-gateway";
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO "redmine-gateway";
GRANT USAGE, SELECT ON SEQUENCE email_addresses_id_seq TO "redmine-gateway";

-- EasyRedmine sequence (only needed if using EasyRedmine)
GRANT USAGE, SELECT ON SEQUENCE easy_twofa_user_schemes_id_seq TO "redmine-gateway";

-- Optional: Grant CONNECT permission to the database
-- GRANT CONNECT ON DATABASE your_redmine_database TO "redmine-gateway";

-- Verify permissions (run these separately to check)
-- SELECT grantee, privilege_type, table_name FROM information_schema.role_table_grants WHERE grantee = 'redmine-gateway';