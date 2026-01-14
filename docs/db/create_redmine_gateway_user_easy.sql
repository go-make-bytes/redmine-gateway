-- SQL Script to create PostgreSQL user 'redmine-gateway' with appropriate permissions
-- FOR EASYREDMINE ONLY
-- This script creates a user with read-only access to all Redmine tables
-- and write/delete permissions only on tables needed by the redmine-gateway service
-- Includes EasyRedmine-specific tables and permissions

-- Create the user (replace 'your_secure_password' with a strong password)
CREATE USER "redmine-gateway" WITH PASSWORD 'your_secure_password';

-- Grant read-only access to all Redmine core tables
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

-- Grant read access to EasyRedmine-specific tables
GRANT SELECT ON easy_twofa_user_schemes TO "redmine-gateway";
GRANT SELECT ON easy_page_modules TO "redmine-gateway";  -- For platform detection

-- Grant write/delete permissions only on tables needed by the service
-- users table: INSERT for LDAP user provisioning
--              UPDATE for password changes (2FA is handled via easy_twofa_user_schemes in EasyRedmine)
GRANT INSERT ON users TO "redmine-gateway";
GRANT UPDATE (hashed_password, salt, passwd_changed_on, must_change_passwd) ON users TO "redmine-gateway";

-- email_addresses table: INSERT and UPDATE for LDAP user provisioning and attribute sync
GRANT INSERT, UPDATE (address, updated_on) ON email_addresses TO "redmine-gateway";

-- EasyRedmine 2FA table: INSERT and UPDATE for 2FA enrollment and TOTP tracking
GRANT INSERT, UPDATE ON easy_twofa_user_schemes TO "redmine-gateway";

-- tokens table: INSERT and DELETE operations for API keys, 2FA backup codes, and security token cleanup
GRANT INSERT, DELETE ON tokens TO "redmine-gateway";

-- Grant usage on sequences for INSERT operations
GRANT USAGE, SELECT ON SEQUENCE tokens_id_seq TO "redmine-gateway";
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO "redmine-gateway";
GRANT USAGE, SELECT ON SEQUENCE email_addresses_id_seq TO "redmine-gateway";
GRANT USAGE, SELECT ON SEQUENCE easy_twofa_user_schemes_id_seq TO "redmine-gateway";

-- Optional: Grant CONNECT permission to the database
-- GRANT CONNECT ON DATABASE your_redmine_database TO "redmine-gateway";

-- Verify permissions (run these separately to check)
-- SELECT grantee, privilege_type, table_name FROM information_schema.role_table_grants WHERE grantee = 'redmine-gateway';

-- Note: This script is for EasyRedmine (all versions)
-- If you're using vanilla/OSS Redmine, use create_redmine_gateway_user_oss.sql instead

-- Key differences from OSS Redmine:
-- 1. EasyRedmine stores 2FA configuration in easy_twofa_user_schemes table instead of users.twofa_* columns
-- 2. Users table doesn't have twofa_scheme, twofa_totp_key, twofa_totp_last_used_at columns
-- 3. Additional easy_page_modules table for platform detection
