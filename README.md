<p align="center">
  <img src="./NodeWarden.svg" alt="NodeWarden Logo" />
</p>

<p align="center">
  Bitwarden-compatible server running on Cloudflare Workers
</p>

<p align="center">
  <a href="https://workers.cloudflare.com/"><img src="https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white" alt="Powered by Cloudflare" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-LGPL--3.0-2ea44f" alt="License: LGPL-3.0" /></a>
  <a href="https://github.com/shuaiplus/NodeWarden/releases/latest"><img src="https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag" alt="Latest Release" /></a>

</p>

<p align="center">
  <a href="https://t.me/NodeWarden_News">Telegram Channel</a> |
  <a href="https://t.me/NodeWarden_Official">Telegram Group</a>
</p>

<p align="center">
  <a href="./README_ZH.md">中文</a> |
  <a href="./CONTRIBUTING.md">Contributing</a> |
  <a href="https://nodewarden.app">Official wiki</a>
</p>

> **Disclaimer**  
> This project is for learning and discussion purposes only. Please back up your vault regularly.  
> This project is not affiliated with Bitwarden. Please do not report NodeWarden issues to the official Bitwarden team.

---

## Feature comparison with the official Bitwarden server

| Feature | Bitwarden Free | NodeWarden | Notes |
|---|---|---|---|
| Web vault | ✅ | ✅ | **Original Web Vault UI** |
| TOTP | ❌ | ✅ | Includes `steam://` support |
| **PWA / offline** | ❌ | ✅ | **Installable, offline** |
| **Passkey login** | ✅ | ✅ | **passwordless auth** |
| API keys | ✅ | ✅ | CLI keys; create and rotate |
| Login 2FA | ✅ | ✅ | TOTP, YubiKey, Passkey; email when mail is configured |
| 2FA recovery codes | ✅ | ✅ | One-time 2FA disable codes |
| Real-time push sync | ✅ | ✅ | All device sync |
| Attachments / Send | ✅ | ✅ | Cloudflare R2 |
| Import / export | ✅ | ✅ | Bitwarden JSON / CSV / **ZIP** |
| **Cloud backup center** | ❌ | ✅ | **Scheduled WebDAV / S3 incrementals** |
| Device management | ✅ | ✅ | **Remove devices; trust controls** |
| Login requests | ✅ | ✅ | **Cross-device login approval/unlock** |
| **Multi-user** | ✅ | ✅ | Invite-code registration |
| Domain rules | ✅ | ✅ | Equivalent domains, global exclusions |
| Fill-assist | ✅ | ✅ | `POST /fill-assist`|
| Organizations / collections / roles | ✅ | ❌ | Not implemented |
| SSO / SCIM / directory | ✅ | ⚠️ | Opt-in OpenID Connect SSO; no SCIM or directory sync |

---

## Tested clients

- ✅ Windows desktop
- ✅ Mobile app
- ✅ Browser extension
- ✅ Linux desktop
- ⚠️ macOS desktop not fully verified yet

---

## Visual quick deploy

1. Fork the NodeWarden repository to your GitHub account
2. Open [Cloudflare Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create)
3. Choose **Continue with GitHub** and select your fork
4. Set **build command** to `npm run build` and **deploy command** to `npm run deploy`
   - `npm run deploy` creates the `nodewarden-attachments` R2 bucket if it does not exist; R2 needs a payment card on the account
5. After deployment finishes, open the generated Workers URL

- The default Workers hostname may be unreachable on some networks. To use a custom domain, add it in [Workers settings](https://dash.cloudflare.com/?to=/:account/workers/services/view/nodewarden/production/settings).

- If the site reports a missing `JWT_SECRET`, add it as a **Secret** in Workers settings. In production use a random string of at least 32 characters; do not use temporary or example values.

- To hide the Web Vault, add a text variable named `HIDE_WEB_VAULT` with the value `1` under **Workers settings → Variables and Secrets**. While enabled, server-hosted frontend pages and static assets return `404 Not Found`, while the login, sync, attachment, icon, notification, and other server endpoints used by Bitwarden clients remain available; an already installed or cached PWA can continue using its local frontend. Delete the variable (or change it to anything other than `1`) to restore the server-hosted Web Vault.

- To close registration, add a text variable named `SIGNUPS_ALLOWED` with the value `false` under **Workers settings → Variables and Secrets**. `POST /api/accounts/register` then answers `403 Registration is disabled`, `/api/config` reports `disableUserRegistration: true`, and the Web Vault hides `#/register`; the single first account on an empty database can still be created, so a fresh deployment is never locked out. Delete the variable (or set it to `true`) to allow invite-only registration again. This repository's `wrangler.toml` ships it as `false`.
Production builds of the web vault also compile the register view, its handlers and the `registerAccount` call out of the bundle (`__SIGNUPS_DISABLED__` is on for `vite build`); `NW_SIGNUPS_DISABLED=0 npm run build` restores the form for a build that needs it, and development builds keep it.

- In this flow you hand code to Cloudflare to build and deploy. `wrangler.toml` in the repo defines binding names; the Worker initializes the D1 schema on first request—no manual SQL upload.


> [!TIP] 
> Attachments and Send files are stored in the `nodewarden-attachments` R2 bucket:
>   | Card required | Max single attachment / Send file | Free tier |
>   |---|---|---|
>   | Yes | 100 MB (soft limit, adjustable) | 10 GB |
>
> R2 bucket names are immutable. If your existing bucket is named differently, either copy its objects into `nodewarden-attachments` or change `bucket_name` in `wrangler.toml`.


## CI and deployment

`.github/workflows/ci.yml` runs on every pull request and on pushes to `main`:

1. **test** — installs dependencies, typechecks the Worker and the web vault, builds the web vault, then runs `npm run test:ci`.
2. **deploy** (pushes to `main` only, after `test` passes) — runs `npm run deploy`, which builds the web vault, creates the attachments bucket if it is missing, and runs `wrangler deploy`.

Repository secrets used by **deploy**:

| Secret | Value |
|---|---|
| `CLOUDFLARE_API_TOKEN` | API token with *Workers Scripts:Edit*, *Workers R2 Storage:Read* and *Write*, *D1:Edit* and *Account Settings:Read* on the account; the "Edit Cloudflare Workers" template covers this |
| `CLOUDFLARE_ACCOUNT_ID` | the Cloudflare account that owns the Worker |

`npm run test:ci` keeps one script out: `test:folder-tree`, whose test file is missing from the tree. Everything it runs has to pass before a deploy starts.

## Single sign-on (OpenID Connect)

Off by default: with `SSO_ENABLED` unset the server behaves exactly as without this feature. When it is on, Bitwarden clients sign in through your identity provider (IdP) with the authorization code flow and PKCE, then unlock the vault with the master password as usual.

1. Register a confidential client at your IdP with the redirect URI `https://<your-domain>/identity/connect/oidc-signin`.
2. Add these under **Workers settings → Variables and Secrets**, with the client secret as a **Secret**:

| Variable | Default | Meaning |
|---|---|---|
| `SSO_ENABLED` | off | `true` turns SSO on |
| `SSO_AUTHORITY` | | The IdP issuer, exactly as `issuer` in its discovery document. `https` only; private, loopback and link-local hosts are refused |
| `SSO_CLIENT_ID` | | Client ID at the IdP |
| `SSO_CLIENT_SECRET` | | Client secret at the IdP |
| `SSO_SCOPES` | `email profile` | Scopes to request; `openid` is always added |
| `SSO_PKCE` | `true` | PKCE between this server and the IdP. The client's own PKCE is always checked |
| `SSO_SIGNUPS_MATCH_EMAIL` | `false` | Link an IdP identity that no account is linked to yet to the account with the same email, if the IdP says the email is verified. The email must be in the ID token; the userinfo endpoint is not read |
| `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION` | `false` | Also match when the IdP sends no `email_verified` claim |
| `SSO_ONLY` | `false` | Refuse password sign-in for everyone but admins |

- SSO signs in to existing accounts only. Accounts are still created by invite registration, which sets the master password and keys; SSO never creates one. An IdP identity (issuer and subject) is linked to one account the first time it signs in through email matching, and later sign-ins use that link alone. Email matching is the only way to link, so with the defaults no account can sign in through SSO.
- Email matching is an account-takeover risk: anyone who holds an IdP account with a verified email equal to a NodeWarden account's email signs in as that account. The vault stays encrypted under the master password, but the session can read encrypted data and change or delete items. Turn matching on only if your IdP verifies emails and users cannot change them, and turn it off again once accounts are linked.
- 2FA still applies after SSO sign-in.
- `SSO_ONLY` locks out every non-admin account that is not linked yet, and every non-admin on a client that cannot use SSO here (web vault, browser extension). Escape hatch: admin accounts keep password sign-in, so an admin can still get in if the IdP is down or their account is not linked. Passkey and API key sign-in are not affected. Deleting `SSO_ONLY` restores password sign-in for everyone.
- The server accepts the mobile (`bitwarden://sso-callback`), desktop and CLI (`http://localhost:8065` to `8070`) callbacks, as Vaultwarden does; no official client has been tested against it yet. The web vault and browser extension finish SSO on the official Bitwarden web vault's `sso-connector.html`, which NodeWarden does not serve, so they are refused. Trusted-device encryption and key connector are not supported.

## FAQ

- **After forking the repository, why can't I see my repository when connecting GitHub to Cloudflare, or why do I get a 404 after selecting it?**  
  This is usually related to how the GitHub fork is identified or how Cloudflare handles repository authorization and synchronization. If the fork keeps a repository name, description, or other information that is very similar to the upstream project, it may be more likely to trigger related restrictions or issues. It is recommended to rename the repository to something different from the upstream project when creating the fork, and change the repository description as well. For example, you can rename it to `2233warden`. If you have already created the fork, you can rename the repository and update its description in the GitHub repository settings, then try connecting it to Cloudflare again.

- **I deleted my deployment and redeployed it. Why does registration require an invite code again?**  
  Deleting the Worker or redeploying it does not automatically delete the persistent data that was already created. The users, invite codes, and related configuration stored in the D1 database are still there, and attachment files stay in the R2 bucket, so the newly deployed Worker continues to read the existing data and enforce the invite-code requirement.  
  If you want to start completely from scratch, you need to delete the corresponding **D1 database and R2 bucket** as well.

- **I configured `JWT_SECRET`, but the page still says it is missing. Why?**  
  Make sure `JWT_SECRET` is configured under **Workers → Settings → Variables and Secrets**, specifically as a **Runtime variable or Secret**, rather than under **Build variables**.  
  Build-time variables are only available during the build process. They are not available to the Worker at runtime, so the build may succeed while the application still reports that `JWT_SECRET` is missing.

- **Why does `JWT_SECRET` seem to disappear after an upgrade or redeployment?**  
  It is recommended to store `JWT_SECRET` as a **Secret** rather than as a plain-text variable. `JWT_SECRET` is a sensitive runtime credential and should not be committed to the repository.  
  If your deployment process recreates or overwrites the Worker variable configuration, ordinary variables may be affected. Secrets are more appropriate for sensitive configuration that needs to remain available across multiple deployments. If the application still reports that `JWT_SECRET` is missing after a redeployment, check **Variables and Secrets** for the current Worker and make sure the Secret is still configured.

---

## How to update

- Manual: open your fork on GitHub; when the sync banner appears, click **Sync fork** → **Update branch**




## CLI deploy

```powershell
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

npm install
npx wrangler login

# The deploy script creates the attachments bucket if it is missing
npm run deploy

# Local development (local R2 and D1)
npm run dev
```

### Optional: outbound mail

Mail is off by default, and then every email-backed route answers 501 as before. Set these as
Worker variables; put the API key and webhook token in **Secrets**
(`npx wrangler secret put RESEND_API_KEY`), never in `wrangler.toml`.

The simplest provider is [Cloudflare Email Sending](https://developers.cloudflare.com/email-service/),
through the `EMAIL` binding that `wrangler.toml` already declares. Onboard your sending domain in
the dashboard and set only `MAIL_FROM` to an address on it. On the Workers Free plan it delivers only
to [verified destination addresses](https://developers.cloudflare.com/email-service/configuration/destination-addresses/),
free and outside the sending quota, which suits a personal vault: verify each account's address.
Mail to any other address fails with 502 until the account is on Workers Paid.

| Variable | Meaning |
|---|---|
| `MAIL_FROM` | Sender address, such as `Vault <vault@example.com>`. Required. |
| `RESEND_API_KEY` | Send through [Resend](https://resend.com). Takes precedence over the webhook. |
| `MAIL_WEBHOOK_URL` | Or POST `{from, to, subject, text, html}` as JSON to this public `https://` URL (no query string; private and loopback hosts are refused). |
| `MAIL_WEBHOOK_TOKEN` | Optional. Sent to the webhook as `Authorization: Bearer <token>`. |

Resend wins over the webhook, and either wins over the `EMAIL` binding.

With mail configured, the server serves email two-step login, email change, account deletion by
emailed link, verification codes for protected actions, and email verification, and it emails a
notice for emergency access invites. Registration stays invite-only: a sign-up
link is only mailed while the server has no users. If mail is turned off later, accounts that use
email two-step login need their recovery code. See `VAULTWARDEN_PARITY.md` for details.

---


## License

LGPL-3.0 License

---

## Credits

- [Bitwarden](https://bitwarden.com/) - Original design and clients
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - Server implementation reference
- [Cloudflare Workers](https://workers.cloudflare.com/) - Serverless platform

---

## Contributors

<a href="https://github.com/shuaiplus/nodewarden/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=shuaiplus/nodewarden" alt="NodeWarden contributors" />
</a>

## Star History

<a href="https://www.star-history.com/?repos=shuaiplus%2FNodeWarden&type=timeline&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=shuaiplus/NodeWarden&type=timeline&theme=dark&legend=top-left&sealed_token=ck0AMqR8EFMjJ6tMbnGDHT5QwMpO85IUuN7i8e82zRRNPtjoLsAAFwVzxmSZwaid97wLUwy56EEiVE9M-OY0cf16bQKBrU9GaauFoOFXGq-vMqcOyk0tIc4b3o1ZGfDw9IH8o6NUxC125TJkjKSLn9fxhFUUeNr1f1El0UcAUcjsMPl_LX80qQrlvQqp" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left&sealed_token=ck0AMqR8EFMjJ6tMbnGDHT5QwMpO85IUuN7i8e82zRRNPtjoLsAAFwVzxmSZwaid97wLUwy56EEiVE9M-OY0cf16bQKBrU9GaauFoOFXGq-vMqcOyk0tIc4b3o1ZGfDw9IH8o6NUxC125TJkjKSLn9fxhFUUeNr1f1El0UcAUcjsMPl_LX80qQrlvQqp" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left&sealed_token=ck0AMqR8EFMjJ6tMbnGDHT5QwMpO85IUuN7i8e82zRRNPtjoLsAAFwVzxmSZwaid97wLUwy56EEiVE9M-OY0cf16bQKBrU9GaauFoOFXGq-vMqcOyk0tIc4b3o1ZGfDw9IH8o6NUxC125TJkjKSLn9fxhFUUeNr1f1El0UcAUcjsMPl_LX80qQrlvQqp" />
 </picture>
</a>
