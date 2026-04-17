INSERT INTO system_settings (setting_key, setting_value, description, created_at, updated_at)
VALUES (
  'subdomain_blacklist',
  'admin,root,api,www,mail,smtp,ftp,ssh,dns,test,demo,dev,stage,prod,blog,forum,shop,status,support,help,docs,cdn,static,assets',
  'Comma-separated list of reserved subdomains that cannot be registered',
  NOW(),
  NOW()
) ON CONFLICT (setting_key) DO NOTHING;
