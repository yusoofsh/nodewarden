# Vaultwarden parity matrix

Target is Vaultwarden 1.0.0 (`src/api/**`). It is measured, not estimated:
`scripts/parity-audit.ts` reads every route attribute from a Vaultwarden checkout and
sends each through this server's real route handlers on an in-memory database.

```sh
tsx --import ./scripts/offline-workers-loader.mjs scripts/parity-audit.ts <vaultwarden-checkout> [--json] [--sso]
```

- **Handled**: a handler answers the route. A 404 for the sample id still counts.
- **Stub**: a catch-all answers every GET with an empty list (`/api/policies`). The feature does not exist.
- **Refused**: the server answers 405 or 501 on purpose (email-backed routes, set-password).
- **Unmatched**: no handler claims the route.

"Handled" means the route exists, not that an official client was run against it.
The admin panel, web, icons and push surfaces are outside this table: this server has
its own `/api/admin/*` and web vault.

## Result

Organizations were removed from this fork after the measurement below. `core/organizations.rs`,
the organization event log and the directory import now answer 404, and
`migrations/0002_drop_organizations.sql` removes their storage. Those rows show the routes as
unmatched; the rest of the table is the last full measurement.

| Vaultwarden file | Handled | Stub | Refused (405/501) | Unmatched |
|---|---|---|---|---|
| core/accounts.rs | 42 | 0 | 1 | 0 |
| core/ciphers.rs | 59 | 0 | 0 | 0 |
| core/emergency_access.rs | 19 | 0 | 0 | 0 |
| core/events.rs | 0 | 0 | 0 | 4 |
| core/folders.rs | 7 | 0 | 0 | 0 |
| core/mod.rs | 9 | 0 | 0 | 0 |
| core/organizations.rs | 0 | 0 | 0 | 69 |
| core/public.rs | 0 | 0 | 0 | 1 |
| core/sends.rs | 11 | 0 | 0 | 0 |
| core/two_factor/authenticator.rs | 4 | 0 | 0 | 0 |
| core/two_factor/duo.rs | 4 | 0 | 0 | 0 |
| core/two_factor/email.rs | 5 | 0 | 0 | 0 |
| core/two_factor/mod.rs | 3 | 0 | 0 | 0 |
| core/two_factor/protected_actions.rs | 2 | 0 | 0 | 0 |
| core/two_factor/webauthn.rs | 6 | 0 | 0 | 0 |
| core/two_factor/yubikey.rs | 4 | 0 | 0 | 0 |
| identity.rs | 10 | 0 | 0 | 0 |

Total 260: handled 185, stub 0, refused 1, unmatched 74

Measured with `--mail` and `--sso`, which configure an email provider and an OpenID provider. Both are off unless an operator sets them (`RESEND_API_KEY` or `MAIL_WEBHOOK_URL` for mail, `SSO_ENABLED` for SSO). Without `--mail` the email-backed routes answer 501, which leaves handled 169 and refused 17. Without either flag it reports handled 164, refused 17 and unmatched 79, because the four SSO routes fall through. Duo needs no flag: its routes answer for every user, and Duo only signs in once a user saves a configuration.

## Not in the Vaultwarden route list

- **SSO.** OpenID Connect sign-in (authorization code with PKCE) serves `/identity/sso/prevalidate`, `/identity/connect/authorize`, `/identity/connect/oidc-signin`, `POST /api/organizations/domain/sso/verified` and the `authorization_code` grant, only when `SSO_ENABLED` is set. It signs in to existing accounts, which unlock with their master password. It refuses what Vaultwarden does beyond that: creating an account through SSO (Vaultwarden then needs `set-password`, which answers 501 here), web and browser clients (they finish on the official web vault's `sso-connector.html`), sessions tied to IdP tokens (Vaultwarden's default; this server issues its own tokens, as with `SSO_AUTH_ONLY_NOT_SESSION`), `SSO_AUDIENCE_TRUSTED`, `SSO_MASTER_PASSWORD_POLICY`, trusted-device encryption and key connector. Bitwarden's own SCIM and Directory Connector sync are licence-gated upstream and Vaultwarden does not ship them.
- **V2 account keys.** Registration, `POST /api/accounts/keys` and both rotation routes accept V2 account keys (signed public key, signature key pair, security state), validated as Vaultwarden does, and profile, sync, the token response and `GET /api/users/{id}/keys` return them. `rotate-user-keys` also upgrades a V1 account in place and stores the upgrade token on the account and on memberships enrolled in account recovery, which `pending-v2-upgrades` and `v2-upgrades` then serve to admins. Unlike Vaultwarden, every rotation here ends all sessions, the V1 to V2 upgrade included. This repo's own `webapp/` decrypts only V1 (AES-CBC-HMAC, type 2) data, so an account upgraded to V2 needs the official clients.
- **Who calls the routes.** Nothing in this repo's `webapp/` calls KDF change, key rotation, security-stamp, self-delete or hibp. They serve official clients only.

## Unhandled and refused routes

<details><summary>core/accounts.rs: refused (1)</summary>

- `POST /api/accounts/set-password` (answers 501, SSO account creation is not supported)

</details>
