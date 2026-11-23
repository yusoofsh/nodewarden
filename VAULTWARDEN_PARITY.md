# Vaultwarden parity matrix

Target is Vaultwarden 1.0.0 (`src/api/**`). It is measured, not estimated:
`scripts/parity-audit.ts` reads every route attribute from a Vaultwarden checkout and
sends each through this server's real route handlers on an in-memory database.

```sh
tsx --import ./scripts/offline-workers-loader.mjs scripts/parity-audit.ts <vaultwarden-checkout> [--json]
```

- **Handled**: a handler answers the route. A 404 for the sample id still counts.
- **Stub**: a catch-all answers every GET with an empty list (`/api/policies`). The feature does not exist.
- **Refused**: the server answers 405 or 501 on purpose (email-backed routes, set-password, V2-only key rotation).
- **Unmatched**: no handler claims the route.

"Handled" means the route exists, not that an official client was run against it.
The admin panel, web, icons and push surfaces are outside this table: this server has
its own `/api/admin/*` and web vault.

## Result

| Vaultwarden file | Handled | Stub | Refused (405/501) | Unmatched |
|---|---|---|---|---|
| core/accounts.rs | 35 | 0 | 8 | 0 |
| core/ciphers.rs | 59 | 0 | 0 | 0 |
| core/emergency_access.rs | 19 | 0 | 0 | 0 |
| core/events.rs | 4 | 0 | 0 | 0 |
| core/folders.rs | 7 | 0 | 0 | 0 |
| core/mod.rs | 9 | 0 | 0 | 0 |
| core/organizations.rs | 68 | 0 | 0 | 1 |
| core/public.rs | 0 | 0 | 0 | 1 |
| core/sends.rs | 11 | 0 | 0 | 0 |
| core/two_factor/authenticator.rs | 4 | 0 | 0 | 0 |
| core/two_factor/duo.rs | 4 | 0 | 0 | 0 |
| core/two_factor/email.rs | 0 | 0 | 5 | 0 |
| core/two_factor/mod.rs | 3 | 0 | 0 | 0 |
| core/two_factor/protected_actions.rs | 0 | 0 | 2 | 0 |
| core/two_factor/webauthn.rs | 6 | 0 | 0 | 0 |
| core/two_factor/yubikey.rs | 4 | 0 | 0 | 0 |
| identity.rs | 3 | 0 | 3 | 4 |

Total 260: handled 236, stub 0, refused 18, unmatched 6

## Not in the Vaultwarden route list

- **SSO.** Vaultwarden implements OIDC login (`sso_auth.rs`, `/identity/connect/authorize`, `/sso/prevalidate`). The unmatched `identity.rs` rows include it. It is a target after organizations, not an exclusion. Bitwarden's own SCIM and Directory Connector sync are licence-gated upstream and Vaultwarden does not ship them.
- **Duo login.** Two-factor provider 2 (Duo Universal Prompt) is offered at `/identity/connect/token` only to users who saved Duo settings. Duo redirects back to `/duo-redirect-connector.html`, which hands the code and state to the client. This repo's `webapp/` has no Duo settings or login screen; official clients drive it.
- **Who calls the routes.** Nothing in this repo's `webapp/` calls KDF change, key rotation, security-stamp, self-delete or hibp. They serve official clients only. Organization features need web vault screens too.

## Unhandled and refused routes

<details><summary>core/accounts.rs: refused (8)</summary>

- `POST /api/accounts/delete-recover-token` (answers 501)
- `POST /api/accounts/delete-recover` (answers 501)
- `POST /api/accounts/email-token` (answers 501)
- `POST /api/accounts/email` (answers 501)
- `POST /api/accounts/key-management/rotate-user-keys` (answers 501)
- `POST /api/accounts/set-password` (answers 501)
- `POST /api/accounts/verify-email-token` (answers 501)
- `POST /api/accounts/verify-email` (answers 501)

</details>

<details><summary>core/organizations.rs: unmatched (1)</summary>

- `POST /api/organizations/domain/sso/verified`

</details>

<details><summary>core/public.rs: unmatched (1)</summary>

- `POST /api/public/organization/import`

</details>

<details><summary>core/two_factor/email.rs: refused (5)</summary>

- `DELETE /api/two-factor/email` (answers 501)
- `POST /api/two-factor/get-email` (answers 501)
- `POST /api/two-factor/send-email-login` (answers 501)
- `POST /api/two-factor/send-email` (answers 501)
- `PUT /api/two-factor/email` (answers 501)

</details>

<details><summary>core/two_factor/protected_actions.rs: refused (2)</summary>

- `POST /api/accounts/request-otp` (answers 501)
- `POST /api/accounts/verify-otp` (answers 501)

</details>

<details><summary>identity.rs: refused (3)</summary>

- `POST /identity/accounts/register/finish` (answers 501)
- `POST /identity/accounts/register/send-verification-email` (answers 501)
- `POST /identity/accounts/register/verification-email-clicked` (answers 501)

</details>

<details><summary>identity.rs: unmatched (4)</summary>

- `GET /identity/connect/authorize`
- `GET /identity/connect/oidc-signin`
- `GET /identity/sso/prevalidate`

</details>
