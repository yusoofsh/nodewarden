# Vaultwarden parity matrix

Target is Vaultwarden 1.0.0 (`src/api/**`). It is measured, not estimated:
`scripts/parity-audit.ts` reads every route attribute from a Vaultwarden checkout and
sends each through this server's real route handlers on an in-memory database.

```sh
tsx --import ./scripts/offline-workers-loader.mjs scripts/parity-audit.ts <vaultwarden-checkout> [--json] [--sso]
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
| core/accounts.rs | 41 | 0 | 2 | 0 |
| core/ciphers.rs | 59 | 0 | 0 | 0 |
| core/emergency_access.rs | 19 | 0 | 0 | 0 |
| core/events.rs | 4 | 0 | 0 | 0 |
| core/folders.rs | 7 | 0 | 0 | 0 |
| core/mod.rs | 9 | 0 | 0 | 0 |
| core/organizations.rs | 69 | 0 | 0 | 0 |
| core/public.rs | 1 | 0 | 0 | 0 |
| core/sends.rs | 11 | 0 | 0 | 0 |
| core/two_factor/authenticator.rs | 4 | 0 | 0 | 0 |
| core/two_factor/duo.rs | 4 | 0 | 0 | 0 |
| core/two_factor/email.rs | 5 | 0 | 0 | 0 |
| core/two_factor/mod.rs | 3 | 0 | 0 | 0 |
| core/two_factor/protected_actions.rs | 2 | 0 | 0 | 0 |
| core/two_factor/webauthn.rs | 6 | 0 | 0 | 0 |
| core/two_factor/yubikey.rs | 4 | 0 | 0 | 0 |
| identity.rs | 10 | 0 | 0 | 0 |

Total 260: handled 258, stub 0, refused 2, unmatched 0

Measured with `--mail` and `--sso`, which configure an email provider and an OpenID provider. Both are off unless an operator sets them (`RESEND_API_KEY` or `MAIL_WEBHOOK_URL` for mail, `SSO_ENABLED` for SSO). Without `--mail` the email-backed routes answer 501 and the run reports handled 242 and refused 18. Without either flag it reports handled 237, refused 18 and unmatched 5, because the four SSO routes fall through. Duo needs no flag: its routes answer for every user, and Duo only signs in once a user saves a configuration.

## Not in the Vaultwarden route list

- **SSO.** OpenID Connect sign-in (authorization code with PKCE) serves `/identity/sso/prevalidate`, `/identity/connect/authorize`, `/identity/connect/oidc-signin`, `POST /api/organizations/domain/sso/verified` and the `authorization_code` grant, only when `SSO_ENABLED` is set. It signs in to existing accounts, which unlock with their master password. It refuses what Vaultwarden does beyond that: creating an account through SSO (Vaultwarden then needs `set-password`, which answers 501 here), web and browser clients (they finish on the official web vault's `sso-connector.html`), sessions tied to IdP tokens (Vaultwarden's default; this server issues its own tokens, as with `SSO_AUTH_ONLY_NOT_SESSION`), `SSO_AUDIENCE_TRUSTED`, `SSO_MASTER_PASSWORD_POLICY`, trusted-device encryption and key connector. Bitwarden's own SCIM and Directory Connector sync are licence-gated upstream and Vaultwarden does not ship them.
- **Who calls the routes.** Nothing in this repo's `webapp/` calls KDF change, key rotation, security-stamp, self-delete or hibp. They serve official clients only. Organization features need web vault screens too.

## Unhandled and refused routes

<details><summary>core/accounts.rs: refused (2)</summary>

- `POST /api/accounts/key-management/rotate-user-keys` (answers 501, V2 key rotation is not implemented; V1 rotation works)
- `POST /api/accounts/set-password` (answers 501, SSO account creation is not supported)

</details>
