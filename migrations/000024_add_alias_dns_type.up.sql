ALTER TABLE dns_records DROP CONSTRAINT IF EXISTS dns_records_type_check;
ALTER TABLE dns_records ADD CONSTRAINT dns_records_type_check CHECK (type IN ('A', 'AAAA', 'CNAME', 'ALIAS', 'MX', 'TXT', 'NS', 'SRV', 'CAA'));
