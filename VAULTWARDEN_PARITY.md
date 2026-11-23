# Vaultwarden parity matrix

Target is Vaultwarden 1.0.0 (`src/api/**`). It is measured, not estimated:
`scripts/parity-audit.ts` reads every route attribute from a Vaultwarden checkout and
sends each through this server's real route handlers on an in-memory database.

```sh
tsx --import ./scripts/offline-workers-loader.mjs scripts/parity-audit.ts <vaultwarden-checkout> [--json] [--mail]
```

- **Handled**: a handler answers the route. A 404 for the sample id still counts.
- **Stub**: a catch-all answers every GET with an empty list (`/api/policies`). The feature does not exist.
- **Refused**: the server answers 405 or 501 on purpose (set-password, V2-only key rotation, and the email-backed routes while mail is unconfigured).
- **Unmatched**: no handler claims the route.

"Handled" means the route exists, not that an official client was run against it.
The admin panel, web, icons and push surfaces are outside this table: this server has
its own `/api/admin/*` and web vault.

## Result

| Vaultwarden file | Handled | Stub | Refused (405/501) | Unmatched |
|---|---|---|---|---|
| core/accounts.rs | 41 | 0 | 2 | 0 |
| core/ciphers.rs | 59 | 0 | 0 | 0 |
| core/emergency_access.rs | 19 | 0 | 0 | 0 |
| core/events.rs | 4 | 0 | 0 | 0 |
| core/folders.rs | 7 | 0 | 0 | 0 |
| core/mod.rs | 9 | 0 | 0 | 0 |
| core/organizations.rs | 68 | 0 | 0 | 1 |
| core/public.rs | 0 | 0 | 0 | 1 |
| core/sends.rs | 11 | 0 | 0 | 0 |
| core/two_factor/authenticator.rs | 4 | 0 | 0 | 0 |
| core/two_factor/duo.rs | 0 | 0 | 0 | 4 |
| core/two_factor/email.rs | 5 | 0 | 0 | 0 |
| core/two_factor/mod.rs | 3 | 0 | 0 | 0 |
| core/two_factor/protected_actions.rs | 2 | 0 | 0 | 0 |
| core/two_factor/webauthn.rs | 6 | 0 | 0 | 0 |
| core/two_factor/yubikey.rs | 4 | 0 | 0 | 0 |
| identity.rs | 6 | 0 | 0 | 4 |

Total 260: handled 248, stub 0, refused 2, unmatched 10

The table is measured with `--mail`: a mail provider configured and outbound fetch stubbed.
Mail is off by default (see the README). Without it, the 16 email-backed routes below answer
501 as before, giving handled 232 and refused 18.

## Not in the Vaultwarden route list

- **SSO.** Vaultwarden implements OIDC login (`sso_auth.rs`, `/identity/connect/authorize`, `/sso/prevalidate`). The unmatched `identity.rs` rows include it. It is a target after organizations, not an exclusion. Bitwarden's own SCIM and Directory Connector sync are licence-gated upstream and Vaultwarden does not ship them.
- **Who calls the routes.** Nothing in this repo's `webapp/` calls KDF change, key rotation, security-stamp, self-delete or hibp. They serve official clients only. Organization features need web vault screens too.

## Unhandled and refused routes

<details><summary>core/accounts.rs: refused (2)</summary>

- `POST /api/accounts/key-management/rotate-user-keys` (answers 501)
- `POST /api/accounts/set-password` (answers 501)

</details>

<details><summary>core/organizations.rs: unmatched (1)</summary>

- `POST /api/organizations/domain/sso/verified`

</details>

<details><summary>core/public.rs: unmatched (1)</summary>

- `POST /api/public/organization/import`

</details>

<details><summary>core/two_factor/duo.rs: unmatched (4)</summary>

- `DELETE /api/two-factor/duo`
- `POST /api/two-factor/duo`
- `POST /api/two-factor/get-duo`
- `PUT /api/two-factor/duo`

</details>

<details><summary>identity.rs: unmatched (4)</summary>

- `GET /identity/connect/authorize`
- `GET /identity/connect/oidc-signin`
- `GET /identity/sso/prevalidate`

</details>

## Email-backed routes

Served only when mail is configured (`MAIL_FROM` plus `RESEND_API_KEY` or `MAIL_WEBHOOK_URL`);
otherwise they answer 501. Handlers live in `src/handlers/email-auth.ts`.

- Email two-step login (`core/two_factor/email.rs`): `get-email`, `send-email`, `PUT`/`DELETE /two-factor/email`, `send-email-login` and login with provider 1.
  `send-email-login` takes email and master password hash only; the auth-request and SSO variants are not served.
- Change email (`email-token`, `email`), `verify-email`, `verify-email-token`, `delete-recover`, `delete-recover-token`, `request-otp`, `verify-otp`.
  Every account counts as verified, so `verify-email-token` only spends its token. Other routes still read `otp` as a master password hash.
- Registration by email (`identity.rs` register trio) stays invite-only: a link is sent only while the server has no users, and `finish` runs the normal registration.
- `resend-new-device-otp` stays 501: new-device verification is not built.
- This repo's `webapp/` has no pages for the verify-email, delete-recover or finish-signup links, or for email two-step setup. Official clients and the API work; the links follow the Bitwarden web vault paths.

