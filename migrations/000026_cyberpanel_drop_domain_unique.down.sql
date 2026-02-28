-- Restore unique constraint (only safe if no duplicate domain_id rows exist)
ALTER TABLE cyberpanel_accounts ADD CONSTRAINT cyberpanel_accounts_domain_id_key UNIQUE (domain_id);
