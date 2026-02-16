-- Add suspended_at and suspend_reason fields to domains table
ALTER TABLE domains ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMP;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS suspend_reason TEXT;
