-- ==============================================================================
-- Kura LMS - roles for Vault's temporary database users (vault-roles.sql)
--
-- Run by docker/vault/init-vault.sh as kura-admin. Safe to run more than once.
--
-- 1. kura_app keeps every runtime permission but can no longer log in. Django
--    logs in as short-lived users ("kura_dyn_...") that Vault creates as
--    members of kura_app, so they get exactly kura_app's permissions.
-- 2. vault_admin is the account Vault uses to create and drop those users.
--    It is NOT a superuser: it may create roles, and the only role it may hand
--    out is kura_app (ADMIN option). It cannot read or change any table itself
--    (INHERIT FALSE, SET FALSE). Its password is set by init-vault.sh and then
--    immediately changed by Vault ("rotate-root"), so only Vault knows it.
-- ==============================================================================

-- 1. Nobody logs in as kura_app any more (a stolen certificate alone is useless).
ALTER ROLE kura_app WITH NOLOGIN;

-- 2. Create vault_admin if it does not exist yet.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') THEN
        CREATE ROLE vault_admin WITH LOGIN CREATEROLE NOINHERIT;
    END IF;
END $$;

-- vault_admin may grant kura_app to the users it creates, but may not use
-- kura_app's permissions itself.
GRANT kura_app TO vault_admin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;

-- vault_admin must be able to connect to the kura database to run its commands.
GRANT CONNECT ON DATABASE kura TO vault_admin;

-- Re-read pg_hba.conf, so the login rules for vault_admin and the kura_dyn_
-- users apply straight away on a database that was already running.
SELECT pg_reload_conf();
