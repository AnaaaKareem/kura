-- ==============================================================================
-- Kura LMS - read-only monitoring login for the metrics collector (Alloy).
-- Run as kura-admin on an EXISTING database; safe to run more than once. A
-- brand-new database gets the same role from init-roles.sql (section 7).
--
-- "alloy" may only read PostgreSQL's own statistics (connections, transactions,
-- database and table sizes, row COUNTS per table) through the built-in
-- pg_monitor role. It cannot read the rows in any table (no grades, users or
-- answers). It has no password: pg_hba.conf only accepts it with Alloy's
-- client certificate (issued by Vault, CN = alloy).
-- ==============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'alloy') THEN
        CREATE ROLE alloy WITH LOGIN NOINHERIT;
    END IF;
END $$;

-- pg_monitor = read PostgreSQL's statistics views; nothing else.
GRANT pg_monitor TO alloy WITH INHERIT TRUE;
GRANT CONNECT ON DATABASE kura TO alloy;

-- Re-read pg_hba.conf so the certificate login rule applies straight away.
SELECT pg_reload_conf();
