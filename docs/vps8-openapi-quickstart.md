# VPS8 DNS OpenAPI Quickstart

Use this when you want OpenDomain DNS CRUD to proxy to VPS8 DNS OpenAPI instead of direct PowerDNS.

## 1) Required env

Add to your `.env`:

```env
# keep existing defaults for NS
DEFAULT_NS1=ns1.example.com
DEFAULT_NS2=ns2.example.com

# switch DNS backend
DNS_PROVIDER=vps8_openapi

# VPS8 DNS OpenAPI endpoint + auth
VPS8_OPENAPI_URL=https://vps8.zz.cd
VPS8_OPENAPI_USER=client
VPS8_OPENAPI_KEY=your-vps8-dnsopenapi-key
```

## 2) What routes are proxied

When `DNS_PROVIDER=vps8_openapi`, these APIs in OpenDomain are proxied to VPS8:

- `GET /api/dns/:domainId/records` -> `POST /api/client/dnsopenapi/record_list`
- `POST /api/dns/:domainId/records` -> `POST /api/client/dnsopenapi/record_create`
- `PUT /api/dns/:domainId/records/:recordId` -> `POST /api/client/dnsopenapi/record_update`
- `DELETE /api/dns/:domainId/records/:recordId` -> `POST /api/client/dnsopenapi/record_delete`

## 3) Important behavior notes

- Existing OpenDomain ownership checks still apply before proxying.
- Domains with custom nameservers are still blocked from panel DNS edits.
- NS records are supported through `record_*` with `type=NS`.
- Creating apex NS (`name=@`) is rejected to match VPS8 policy.

## 4) Error mapping

OpenDomain maps common VPS8 errors to HTTP status:

- validation errors -> 400
- not found -> 404
- suspended/disabled -> 403
- rate limit -> 429
- upstream/network failures -> 502

## 5) Rollback

Set:

```env
DNS_PROVIDER=powerdns
```

Then restart OpenDomain service.
