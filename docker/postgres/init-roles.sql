-- ==============================================================================
-- Kura LMS - PostgreSQL Least-Privilege Roles & REVOKE Rules (init-roles.sql)
--
-- Security:
-- 1. Explicit REVOKE rules: Revokes CREATE on public schema from PUBLIC.
-- 2. Scoped Role Accounts:
--    - kura_app: holds the runtime application permissions (SELECT, INSERT, UPDATE,
--      DELETE on tables; USAGE, SELECT, UPDATE on sequences; NO DDL / DROP / ALTER).
--      It is NOLOGIN: nobody logs in as kura_app. Vault creates short-lived
--      "kura_dyn_..." users that are members of it (docker/postgres/vault-roles.sql).
--    - kura_migrator: schema migration role (used for DDL / migrations only).
--    - kura_readonly: audit, reporting, and replica read-only role.
-- 3. Enables pgAudit extension for tamper-resistant database audit trails.
-- ==============================================================================

-- 1. Enable pgAudit extension
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- 2. Revoke default public creation privileges on public schema
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE kura FROM PUBLIC;

-- 3. Create scoped application roles
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kura_app') THEN
        CREATE ROLE kura_app WITH NOLOGIN NOINHERIT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kura_migrator') THEN
        CREATE ROLE kura_migrator WITH LOGIN CREATEDB;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kura_readonly') THEN
        CREATE ROLE kura_readonly WITH LOGIN NOINHERIT;
    END IF;
END $$;

-- 4. Grant runtime DML permissions to kura_app (no DDL permissions)
GRANT CONNECT ON DATABASE kura TO kura_app;
GRANT USAGE ON SCHEMA public TO kura_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kura_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO kura_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kura_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO kura_app;

-- 5. Grant DDL permissions to kura_migrator
GRANT ALL PRIVILEGES ON DATABASE kura TO kura_migrator;
GRANT ALL PRIVILEGES ON SCHEMA public TO kura_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO kura_migrator;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO kura_migrator;

-- 6. Grant read-only reporting permissions to kura_readonly
GRANT CONNECT ON DATABASE kura TO kura_readonly;
GRANT USAGE ON SCHEMA public TO kura_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO kura_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO kura_readonly;

-- 7. Read-only monitoring login for the metrics collector (Alloy).
CREATE ROLE alloy WITH LOGIN NOINHERIT;
GRANT pg_monitor TO alloy WITH INHERIT TRUE;
GRANT CONNECT ON DATABASE kura TO alloy;
