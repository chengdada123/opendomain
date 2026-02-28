-- Drop the UNIQUE constraint on domain_id in cyberpanel_accounts.
-- A domain can have multiple accounts over time (e.g. terminate → re-apply),
-- so only a non-unique index is needed.
ALTER TABLE cyberpanel_accounts DROP CONSTRAINT IF EXISTS cyberpanel_accounts_domain_id_key;

-- Hard-delete any residual terminated records so re-apply works cleanly.
DELETE FROM cyberpanel_accounts WHERE status = 'terminated';
