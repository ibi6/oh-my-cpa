# ADR 0105: A customer portal with its own accounts, issuing keys into CPA's key list

- Status: Proposed
- Date: 2026-10-22

## Context

Oh My CPA is a single-operator console: one sign-in, derived from CPA's management
key, sees and changes everything. Operators who resell or share a gateway want what
new-api style distribution systems offer: customer accounts that sign in on their
own, issue their own API keys and read their own usage, without ever seeing the
operator's credentials, providers or other customers.

CPA authenticates clients against one flat list, `access.api-keys`, and reports the
client key of every request in its usage stream, which Oh My CPA already stores as
an HMAC fingerprint (`usage_events.api_group_key`, purpose `usage-api-key`). CPA has
no notion of a user or a per-key owner. A FrontendAuth plugin inside CPA could
authenticate keys against Oh My CPA directly, and is the eventual target, but it is
a separate deliverable with its own release cadence.

## Decision

Add a customer portal as a separate surface of the same process, in three layers
that keep its footprint in shared files to a few lines:

- **Accounts and sessions** (`internal/portal`, `internal/repository/portal.go`,
  migration 900). Customer accounts have a username (case-insensitive unique), a
  PBKDF2-SHA256 password hash (600 000 iterations, standard library only), a status
  and a key limit. Sessions are server-side rows keyed by the SHA-256 of a random
  token in the `omc_portal_session` cookie (HttpOnly, SameSite=Strict, Secure under
  an `https` public URL). A password change, a password reset or a disable raises
  the account's `auth_version` and deletes its sessions in the same transaction;
  a customer's own password change keeps only the session that made it.
- **Keys** (`portal_api_keys`). A key is `sk-omc-` plus 40 base62 characters. Only
  its usage fingerprint, a display prefix and its last four characters are stored;
  the plaintext is returned once, in the create response. Creation inserts the key
  as `pending`, appends the plaintext to CPA's `access.api-keys` through the same
  management write path the console's key page uses (write gate, revision check,
  pre-write configuration backup), and deletes the row again if CPA refuses, so no
  key is handed out that the gateway never accepted. Revocation stands even when
  CPA is unreachable; the key is marked `failed` and the reconciler retries the
  removal. A background reconciler (every `OMCPA_PORTAL_SYNC_INTERVAL`) removes
  unwanted keys (revoked, expired, account disabled) and marks wanted keys absent
  from CPA as `missing`. It only ever removes entries whose fingerprint a portal key
  owns; operator keys are never touched.
- **Attribution** (migration 901). An `AFTER INSERT` trigger on `usage_events`
  matches `api_group_key` against portal key fingerprints, writes
  `portal_user_id` / `portal_key_id` on the record, upserts the permanent per-UTC-day
  rollup `portal_usage_daily` (user, key, model), and bumps the key's request count.
  The capture pipeline needs no change and attribution is exactly as atomic as the
  record. Cost is the record's locked `cost_nanos`.

The HTTP surface is split by session, not by permission flags:

- `/api/portal/*` is the customer surface. It reads only the `omc_portal_session`
  cookie; non-GET requests require a same-origin request. Request records are served
  through a restricted DTO (time, key, model, result, tokens, latency, cost when
  `OMCPA_PORTAL_SHOW_COST` allows) that omits provider, credential, endpoint, client
  address, user agent and upstream error bodies.
- `/api/v1/portal/*` is the operator's account management, inside `/api/v1` behind
  the operator session. Every write is audited (`portal.*`), and the attempt record
  must be written before the change is made.

The operator's request log gains a `portal_user` filter and facet. The SPA mounts a
separate application under `<base>/portal` before the console's `AuthGate`, so the
portal never renders the console shell or calls an operator endpoint.

The portal is off by default (`OMCPA_PORTAL_ENABLED=false`) and forced off in demo
mode, where every portal route is refused. Registration is `off` (operator-created
accounts only), `invite` (single- or multi-use codes, redeemed atomically with the
account insert) or `open`.

Migrations are numbered 900 and 901 so a downstream fork does not collide with the
upstream's sequential numbering; the runner applies any unapplied version.

## Consequences

- With the portal disabled nothing changes: no routes answer, the reconciler does
  not run, and the trigger costs one indexed probe per ingested record.
- Disabling the portal does not remove keys it already put into CPA; they keep
  working until revoked (or until the operator removes them from the key page).
- A key removed from CPA by hand, or removed because its account was disabled,
  cannot be restored: the plaintext is not stored. The customer issues a new key.
- Daily totals are UTC days, the grain of `usage_facts_daily`; record-level views
  are bounded by `OMCPA_USAGE_RETENTION_DAYS`, the daily rollup is permanent.
- Every key issue and revoke rewrites CPA's configuration and takes a backup, so a
  very high key churn is bounded by the configuration write path. The FrontendAuth
  plugin (a later phase) removes this by authenticating keys without editing CPA's
  configuration, and adds balance and quota enforcement, which this phase does not
  have: usage is attributed and shown, never limited or billed.
- An upstream migration that rebuilds `usage_events` would drop the two portal
  columns, their index and the trigger; such a migration must be followed by one
  that restores them.
