# Design: Per-CA CN Uniqueness + Cert Lookup by Common Name

Date: 2026-06-17

## Problem

There is no API to find a certificate's id given its common name (CN). The
server already refuses duplicate CNs, so callers expect a CN to map to a single
cert, but the only way to discover that cert's id is to list all certs and scan.

While designing the lookup, a pre-existing bug surfaced: CN uniqueness is
enforced **globally** across both the `certificate_authorities` and
`certificates` tables (see `db::common_name_exists`). It should be scoped:

- A CA's CN should be unique **among CAs**.
- A cert's CN should be unique **within its own CA** (the same cert CN may be
  reused under a different CA).

## Goals

1. Fix CN uniqueness to be correctly scoped (CA-among-CAs, cert-within-CA).
2. Add an endpoint to look up a cert id by CN under a given CA.

## Non-Goals

- No change to how CNs are stored or to the `subject` field.
- No bulk/prefix/wildcard search — exact (case-insensitive, trimmed) match only.
- The lookup is not folded into `GET /certs`; it is a dedicated route.

## Matching Semantics

All CN comparisons (uniqueness checks and the lookup) use the same predicate the
existing uniqueness check uses, so the lookup always agrees with what the server
considers a duplicate:

```
lower(trim(common_name)) = lower(trim(<input>))
```

Only non-deleted rows participate. The lookup additionally requires the parent
CA to be non-deleted (consistent with `db::get_cert`).

## Change 1: Scoped CN Uniqueness (bug fix)

### db.rs

Replace `common_name_exists(common_name) -> Result<bool>` with two scoped
methods:

- `ca_common_name_exists(common_name: &str) -> Result<bool>`
  - Counts non-deleted rows in `certificate_authorities` matching the predicate.
- `cert_common_name_exists(ca_id: &str, common_name: &str) -> Result<bool>`
  - Counts non-deleted rows in `certificates` where `ca_id = ?1` matching the
    predicate.

### service.rs

Split `ensure_unique_common_name(cn)` into:

- `ensure_unique_ca_common_name(cn)` → uses `ca_common_name_exists`.
- `ensure_unique_cert_common_name(ca_id, cn)` → uses `cert_common_name_exists`.

Error message stays `common name already exists: <cn>`.

Rewire the four call sites:

| Call site (service.rs)      | New check                                   |
|-----------------------------|---------------------------------------------|
| `create_ca` (~line 222)     | `ensure_unique_ca_common_name`              |
| `import_ca` (~line 302)     | `ensure_unique_ca_common_name`              |
| `create_cert` (~line 456)   | `ensure_unique_cert_common_name(ca_id, ..)` |
| `import_cert` (~line 574)   | `ensure_unique_cert_common_name(ca_id, ..)` |

Behavioral result:

- CA CN unique among CAs; no longer collides with cert CNs.
- Cert CN unique within its CA; the same cert CN is allowed under different CAs.
- A cert CN may equal its own CA's CN (no cross-table check).

## Change 2: Cert Lookup by CN

### Route

`GET /api/cas/{ca_id}/certs_by_cn?cn=<cn>`

- CN travels as a query parameter (handles dots, slashes, spaces, wildcards
  without path-encoding hazards).
- Dedicated route, not an overload of `GET /api/cas/{ca_id}/certs` (which
  returns an array; this returns a single object or 404).
- Viewer auth, like other GET endpoints (`api_view`).

### Responses

| Condition                         | Status | Body                              |
|-----------------------------------|--------|-----------------------------------|
| Match found                       | 200    | `{ "data": { "id": "<cert_id>" } }` |
| No match / unknown or deleted CA  | 404    | standard API error envelope       |
| `cn` missing or empty/whitespace  | 400    | standard API error envelope       |

### db.rs

`find_cert_id_by_cn(ca_id: &str, common_name: &str) -> Result<Option<String>>`

- `SELECT id FROM certificates WHERE ca_id = ?1 AND deleted = 0 AND
  lower(trim(common_name)) = lower(trim(?2)) AND (SELECT deleted FROM
  certificate_authorities WHERE id = ?1) = 0` → first row's id (uniqueness
  guarantees at most one).

### service.rs

`find_cert_id_by_cn(ca_id: &str, cn: &str) -> Result<Option<String>>` delegating
to the db method.

### web.rs

- Add the route to the `/api` router.
- New handler `api_find_cert_by_cn` using a `Query` extractor for `cn`.
- Empty/whitespace `cn` → `400` (`api_error_status` with `invalid_query`).
- `None` from service → `404` (`not_found`).
- `Some(id)` → `api_success({ "id": id })`.

## Change 3: Supporting

### OpenAPI

Add the `/api/cas/{ca_id}/certs_by_cn` GET path (with the `cn` query parameter,
200 and 404 responses) to `openapi_spec_json` so it appears in the Swagger
explorer.

## Testing

Tests live inline in `#[cfg(test)]` modules (matching the codebase convention).

Uniqueness (db.rs / service.rs):
- Two different CAs may each hold a cert with the same CN.
- Two certs with the same CN under one CA are rejected.
- Two CAs with the same CN are rejected.
- A cert CN equal to a different CA's CN is allowed.
- Matching is case-insensitive and trim-insensitive.

Lookup:
- Existing CN → 200 with the correct id.
- Case/whitespace-variant CN → still matches.
- Unknown CN → 404.
- Missing/empty `cn` → 400.
- CN that exists under a different CA → 404 for this CA.

## Risks

- Existing deployments may currently hold data that violates the new (looser)
  rules in ways that are fine, or the old (stricter) global rule may have masked
  intended duplicates. The change only loosens constraints, so no existing data
  becomes invalid. No migration required.
