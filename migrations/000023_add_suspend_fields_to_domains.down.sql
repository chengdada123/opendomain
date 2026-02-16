-- Remove suspended_at and suspend_reason fields from domains table
ALTER TABLE domains DROP COLUMN IF EXISTS suspend_reason;
ALTER TABLE domains DROP COLUMN IF EXISTS suspended_at;
