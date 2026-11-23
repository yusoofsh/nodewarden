# Vaultwarden parity matrix

Target is Vaultwarden 1.0.0 (`src/api/**`). It is measured, not estimated:
`scripts/parity-audit.ts` reads every route attribute from a Vaultwarden checkout and
sends each through this server's real route handlers on an in-memory database.

```sh
tsx --import ./scripts/offline-workers-loader.mjs scripts/parity-audit.ts <vaultwarden-checkout> [--json]
```

- **Handled**: a handler answers the route. A 404 for the sample id still counts.
- **Stub**: a catch-all answers every GET with an empty list (`/api/organizations`, `/api/collections`, `/api/policies`). The feature does not exist.
- **Refused**: the server answers 405 or 501 on purpose (email-backed routes, set-password).
- **Unmatched**: no handler claims the route.

"Handled" means the route exists, not that an official client was run against it.
The admin panel, web, icons and push surfaces are outside this table: this server has
its own `/api/admin/*` and web vault.

## Result

| Vaultwarden file | Handled | Stub | Refused (405/501) | Unmatched |
|---|---|---|---|---|
| core/accounts.rs | 32 | 0 | 5 | 6 |
| core/ciphers.rs | 32 | 0 | 0 | 27 |
| core/emergency_access.rs | 19 | 0 | 0 | 0 |
| core/events.rs | 0 | 2 | 0 | 2 |
| core/folders.rs | 5 | 0 | 0 | 2 |
| core/mod.rs | 8 | 0 | 0 | 1 |
| core/organizations.rs | 0 | 28 | 0 | 41 |
| core/public.rs | 0 | 0 | 0 | 1 |
| core/sends.rs | 11 | 0 | 0 | 0 |
| core/two_factor/authenticator.rs | 4 | 0 | 0 | 0 |
| core/two_factor/duo.rs | 0 | 0 | 0 | 4 |
| core/two_factor/email.rs | 0 | 0 | 5 | 0 |
| core/two_factor/mod.rs | 2 | 0 | 0 | 1 |
| core/two_factor/protected_actions.rs | 0 | 0 | 2 | 0 |
| core/two_factor/webauthn.rs | 5 | 0 | 0 | 1 |
| core/two_factor/yubikey.rs | 4 | 0 | 0 | 0 |
| identity.rs | 3 | 0 | 3 | 4 |

Total 260: handled 125, stub 30, refused 15, unmatched 90

## Not in the Vaultwarden route list

- **SSO.** Vaultwarden implements OIDC login (`sso_auth.rs`, `/identity/connect/authorize`, `/sso/prevalidate`). The unmatched `identity.rs` rows include it. It is a target after organizations, not an exclusion. Bitwarden's own SCIM and Directory Connector sync are licence-gated upstream and Vaultwarden does not ship them.
- **Who calls the routes.** Nothing in this repo's `webapp/` calls KDF change, key rotation, security-stamp, self-delete, hibp or emergency access. They serve official clients only. Organization features need web vault screens too.

## Unhandled and refused routes

<details><summary>core/accounts.rs: refused (5)</summary>

- `POST /api/accounts/email-token`
- `POST /api/accounts/profile`
- `POST /api/accounts/set-password`
- `POST /api/accounts/verify-email`
- `POST /api/accounts/verify-email-token`

</details>

<details><summary>core/accounts.rs: unmatched (6)</summary>

- `GET /api/accounts/key-management/key-rotation-data`
- `POST /api/accounts/delete-recover`
- `POST /api/accounts/delete-recover-token`
- `POST /api/accounts/email`
- `POST /api/accounts/key-management/rotate-user-keys`
- `PUT /api/accounts/avatar`

</details>

<details><summary>core/ciphers.rs: unmatched (27)</summary>

- `DELETE /api/ciphers/<cipher_id>/admin`
- `DELETE /api/ciphers/<cipher_id>/attachment/<attachment_id>/admin`
- `DELETE /api/ciphers/admin`
- `GET /api/ciphers/<cipher_id>/admin`
- `GET /api/ciphers/<cipher_id>/attachment/<attachment_id>/admin`
- `POST /api/ciphers/<cipher_id>/admin`
- `POST /api/ciphers/<cipher_id>/attachment-admin`
- `POST /api/ciphers/<cipher_id>/attachment/<attachment_id>/delete-admin`
- `POST /api/ciphers/<cipher_id>/attachment/<attachment_id>/share`
- `POST /api/ciphers/<cipher_id>/collections`
- `POST /api/ciphers/<cipher_id>/collections-admin`
- `POST /api/ciphers/<cipher_id>/collections_v2`
- `POST /api/ciphers/<cipher_id>/delete-admin`
- `POST /api/ciphers/admin`
- `POST /api/ciphers/delete-admin`
- `POST /api/ciphers/purge`
- `PUT /api/ciphers/<cipher_id>/admin`
- `PUT /api/ciphers/<cipher_id>/collections`
- `PUT /api/ciphers/<cipher_id>/collections-admin`
- `PUT /api/ciphers/<cipher_id>/collections_v2`
- `PUT /api/ciphers/<cipher_id>/delete-admin`
- `PUT /api/ciphers/<cipher_id>/restore-admin`
- `PUT /api/ciphers/<cipher_id>/share`
- `PUT /api/ciphers/delete-admin`
- `PUT /api/ciphers/restore-admin`
- `PUT /api/ciphers/share`

</details>

<details><summary>core/events.rs: stub (2)</summary>

- `GET /api/organizations/<org_id>/events`
- `GET /api/organizations/<org_id>/users/<member_id>/events`

</details>

<details><summary>core/events.rs: unmatched (2)</summary>

- `GET /api/ciphers/<cipher_id>/events`
- `POST /api/collect`

</details>

<details><summary>core/folders.rs: unmatched (2)</summary>

- `POST /api/folders/<folder_id>`
- `POST /api/folders/<folder_id>/delete`

</details>

<details><summary>core/mod.rs: unmatched (1)</summary>

- `GET /api/now`

</details>

<details><summary>core/organizations.rs: stub (28)</summary>

- `GET /api/collections`
- `GET /api/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password`
- `GET /api/organizations/<_org_id>/billing/vnext/self-host/metadata`
- `GET /api/organizations/<_org_id>/billing/vnext/warnings`
- `GET /api/organizations/<identifier>/auto-enroll-status`
- `GET /api/organizations/<org_id>`
- `GET /api/organizations/<org_id>/collections`
- `GET /api/organizations/<org_id>/collections/<col_id>/details`
- `GET /api/organizations/<org_id>/collections/<col_id>/users`
- `GET /api/organizations/<org_id>/collections/details`
- `GET /api/organizations/<org_id>/export`
- `GET /api/organizations/<org_id>/groups`
- `GET /api/organizations/<org_id>/groups/<group_id>`
- `GET /api/organizations/<org_id>/groups/<group_id>/details`
- `GET /api/organizations/<org_id>/groups/<group_id>/users`
- `GET /api/organizations/<org_id>/groups/details`
- `GET /api/organizations/<org_id>/keys`
- `GET /api/organizations/<org_id>/policies`
- `GET /api/organizations/<org_id>/policies/<pol_type>`
- `GET /api/organizations/<org_id>/policies/master-password`
- `GET /api/organizations/<org_id>/policies/token`
- `GET /api/organizations/<org_id>/private-key`
- `GET /api/organizations/<org_id>/public-key`
- `GET /api/organizations/<org_id>/users`
- `GET /api/organizations/<org_id>/users/<member_id>`
- `GET /api/organizations/<org_id>/users/<member_id>/reset-password-details`
- `GET /api/organizations/<org_id>/users/keys/pending-v2-upgrades`
- `GET /api/organizations/<org_id>/users/mini-details`

</details>

<details><summary>core/organizations.rs: unmatched (41)</summary>

- `DELETE /api/organizations/<org_id>`
- `DELETE /api/organizations/<org_id>/collections`
- `DELETE /api/organizations/<org_id>/collections/<col_id>`
- `DELETE /api/organizations/<org_id>/groups`
- `DELETE /api/organizations/<org_id>/groups/<group_id>`
- `DELETE /api/organizations/<org_id>/users`
- `DELETE /api/organizations/<org_id>/users/<member_id>`
- `GET /api/ciphers/organization-details`
- `GET /api/ciphers/organization-details/assigned`
- `GET /api/plans`
- `POST /api/ciphers/bulk-collections`
- `POST /api/ciphers/import-organization`
- `POST /api/organizations`
- `POST /api/organizations/<org_id>/api-key`
- `POST /api/organizations/<org_id>/collections`
- `POST /api/organizations/<org_id>/collections/bulk-access`
- `POST /api/organizations/<org_id>/groups`
- `POST /api/organizations/<org_id>/keys`
- `POST /api/organizations/<org_id>/leave`
- `POST /api/organizations/<org_id>/rotate-api-key`
- `POST /api/organizations/<org_id>/users/<member_id>/accept`
- `POST /api/organizations/<org_id>/users/<member_id>/confirm`
- `POST /api/organizations/<org_id>/users/<member_id>/reinvite`
- `POST /api/organizations/<org_id>/users/confirm`
- `POST /api/organizations/<org_id>/users/invite`
- `POST /api/organizations/<org_id>/users/keys/v2-upgrades`
- `POST /api/organizations/<org_id>/users/public-keys`
- `POST /api/organizations/<org_id>/users/reinvite`
- `POST /api/organizations/domain/sso/verified`
- `PUT /api/organizations/<org_id>`
- `PUT /api/organizations/<org_id>/collections/<col_id>`
- `PUT /api/organizations/<org_id>/groups/<group_id>`
- `PUT /api/organizations/<org_id>/policies/<pol_type>`
- `PUT /api/organizations/<org_id>/users/<member_id>`
- `PUT /api/organizations/<org_id>/users/<member_id>/recover-account`
- `PUT /api/organizations/<org_id>/users/<member_id>/restore`
- `PUT /api/organizations/<org_id>/users/<member_id>/restore/vnext`
- `PUT /api/organizations/<org_id>/users/<member_id>/revoke`
- `PUT /api/organizations/<org_id>/users/<user_id>/reset-password-enrollment`
- `PUT /api/organizations/<org_id>/users/restore`
- `PUT /api/organizations/<org_id>/users/revoke`

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

<details><summary>core/two_factor/email.rs: refused (5)</summary>

- `DELETE /api/two-factor/email`
- `POST /api/two-factor/get-email`
- `POST /api/two-factor/send-email`
- `POST /api/two-factor/send-email-login`
- `PUT /api/two-factor/email`

</details>

<details><summary>core/two_factor/mod.rs: unmatched (1)</summary>

- `GET /api/two-factor/get-device-verification-settings`

</details>

<details><summary>core/two_factor/protected_actions.rs: refused (2)</summary>

- `POST /api/accounts/request-otp`
- `POST /api/accounts/verify-otp`

</details>

<details><summary>core/two_factor/webauthn.rs: unmatched (1)</summary>

- `DELETE /api/two-factor/webauthn/all`

</details>

<details><summary>identity.rs: refused (3)</summary>

- `POST /identity/accounts/register/finish`
- `POST /identity/accounts/register/send-verification-email`
- `POST /identity/accounts/register/verification-email-clicked`

</details>

<details><summary>identity.rs: unmatched (4)</summary>

- `GET /identity/connect/authorize`
- `GET /identity/connect/oidc-signin`
- `GET /identity/sso/prevalidate`

</details>

## Order of work

1. Organizations, as vertical slices that each ship with a web vault screen: create an organization and see it in sync, then collections, members, sharing an item to a collection, groups and policies. Cipher access goes through one access function covered by a role by collection by route test, before anything is parallelized.
2. Emergency access (done, without email: invites go to existing accounts and are accepted at once, as in Vaultwarden with mail off).
3. Email-backed routes (verify email, delete-recover, email two-factor, new-device OTP), which need an outbound mail provider chosen by the operator.
4. Duo, which needs a Duo account to test.
5. SSO.

## Verification

CI on this repository runs CodeQL and `security-extra` only. It does not run `npm run test:*` or exercise client behaviour. Each change is tested locally on `node:sqlite`, which is not D1, and should be run under `wrangler dev` before a deploy.
