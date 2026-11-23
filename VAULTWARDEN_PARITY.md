# Vaultwarden parity matrix

Target is Vaultwarden 1.0.0 (`src/api/**`), not `bitwarden/server`. Its enterprise
parts (SSO, SCIM, directory connector sync) are licence-gated upstream. Vaultwarden
itself ships only a minimal SSO and no SCIM, so they are not targets here.

Method: 298 route attributes were extracted from Vaultwarden's `src/api` and each
was text-matched against `src/`. The match is a heuristic. Dynamic NodeWarden routes
use regexes, so rows marked "check" need a manual look. Treat counts as
upper bounds on what is missing.

## Summary

| Vaultwarden area | Routes | Likely missing | Status |
|---|---|---|---|
| Accounts, devices, auth requests | 43 | 15 | partial |
| Ciphers, attachments, folders | 65 | 35 (many are `/admin` org variants) | partial |
| Sends | 11 | 2 | mostly done |
| Two-factor (TOTP, YubiKey, WebAuthn, email) | 29 | 1 | done |
| Two-factor Duo | 4 | 4 | not started |
| Organizations, collections, members, groups, policies | 69 | 64 | not started (stubbed empty) |
| Emergency access | 19 | 19 | not started |
| Events and org public API | 5 | 4 | not started |
| Admin panel | 26 | 20 | different design (own `/api/admin/*`) |
| Identity, web, icons, notifications | 21 | 10 | mostly done |

Organizations are stubs today: `/api/organizations`, `/api/collections` and
`/api/policies` return empty lists, and `sync` and the profile emit empty
`organizations`, `collections` and `policies`.

## Gaps by class

### 1. Personal-vault routes official clients may call (do first)

Verified absent in `src/`: `POST /accounts/security-stamp`,
`/accounts/key-management/rotate-user-account-keys` and `/rotate-user-keys`,
`GET /accounts/key-management/key-rotation-data`, `/accounts/delete-recover[-token]`,
`GET /users/{id}/public-key`, `/users/{id}/keys`, `GET /hibp/breach`, `GET /alive`,
`GET /tasks`, `PUT /accounts/avatar`, `POST /sends/access/file/{id}`,
`DELETE /two-factor/webauthn/all`, `GET /auth-requests/{id}/response`,
`/ciphers/{id}/details`, `/ciphers/{id}/share`, `/ciphers/share`,
`/ciphers/{id}/attachment-admin`.

Check by hand (matched a substring only): `/ciphers/{id}/partial`, `/ciphers/purge`,
`/devices/identifier/{id}/token`, attachment `share` and `delete` variants.

### 2. Organization family (needs a stack, see below)

Organizations, members and invites, collections, groups, policies, org ciphers
(`/ciphers/*/admin`, `/collections`, `/share`), org keys, org import, org export,
`/public/organization/import`, and the profile, `sync` and `config` fields that
advertise them.

### 3. Emergency access

All 19 routes. Depends on user public keys (class 1) and email delivery.

### 4. Events

`/organizations/{id}/events`, `/ciphers/{id}/events`, `/collect`. Depends on
organizations.

### 5. Duo two-factor

4 routes. Needs a Duo account to test, so lowest priority.

### 6. Admin panel

Vaultwarden's `/admin` is a server-rendered settings UI. NodeWarden has its own
`/api/admin/*` and the web vault admin pages. Parity here means equivalent
capability, not the same routes. Not scheduled.

## Order of work

1. Class 1 routes, one small PR each, with a test script under `scripts/`.
2. Organizations as a stack, each PR ending in a check:
   1. Schema (`storage-schema.ts`, `migrations/`, `STORAGE_SCHEMA_VERSION`) and
      the backup export and import whitelists.
   2. Organization, membership and key endpoints.
   3. Collections and collection access.
   4. Organization ciphers in `/sync` and the cipher handlers.
   5. Web vault UI and i18n.
   6. Policies, groups and events.
3. Emergency access.
4. Duo.

## Verification

CI here runs CodeQL, `security-extra` and the domain sync. It does not run
`npm run test:*` or exercise client behavior. Each PR must be run locally against
`wrangler dev` with an official client or the `bw` CLI. Green CI means the code
scanners passed and nothing else.
