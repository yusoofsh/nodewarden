#!/usr/bin/env node
/**
 * Copy attachment and send-file blobs from an R2 bucket into the ATTACHMENTS_KV
 * namespace, for deployments that still hold files in R2.
 *
 * KV is the only blob backend now, so objects left in R2 are invisible to the
 * Worker until they are copied over.
 *
 * Usage:
 *   node scripts/migrate-r2-to-kv.cjs --dry-run
 *   node scripts/migrate-r2-to-kv.cjs
 *
 * Auth, in order of precedence:
 *   CLOUDFLARE_API_TOKEN (needs R2 read and Workers KV write)
 *   `wrangler login` (the OAuth token from `wrangler auth token`)
 * The account id comes from CLOUDFLARE_ACCOUNT_ID, else `wrangler whoami`.
 *
 * Options:
 *   --bucket <name>        R2 bucket to read (default: nodewarden-attachments)
 *   --namespace-id <id>    KV namespace to write (default: the id pinned in wrangler.toml)
 *   --prefix <prefix>      Only objects with this key prefix
 *   --dry-run              List what would be copied, write nothing
 *
 * Objects over the 25 MiB KV limit are reported and skipped. Objects already in
 * KV are overwritten, so the script is safe to re-run. R2 is only read; delete
 * objects yourself once the copy is verified.
 */
const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const CONFIG = path.resolve(__dirname, '..', 'wrangler.toml');
const KV_MAX_OBJECT_BYTES = 25 * 1024 * 1024;
const DEFAULT_BUCKET = 'nodewarden-attachments';
const API = 'https://api.cloudflare.com/client/v4';

function parseArgs(argv) {
  const options = { bucket: DEFAULT_BUCKET, prefix: '', namespaceId: '', dryRun: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') options.dryRun = true;
    else if (arg === '--bucket') options.bucket = argv[++i];
    else if (arg === '--prefix') options.prefix = argv[++i] || '';
    else if (arg === '--namespace-id') options.namespaceId = argv[++i];
    else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new Error(`[migrate-r2-to-kv] unknown argument: ${arg}`);
  }
  return options;
}

function wrangler(args) {
  return execSync(`npx wrangler ${args}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
}

function resolveToken() {
  if (process.env.CLOUDFLARE_API_TOKEN) return process.env.CLOUDFLARE_API_TOKEN;
  try {
    const raw = wrangler('auth token --json').trim();
    const parsed = JSON.parse(raw);
    const token = parsed.token || parsed.oauth_token || parsed.api_token;
    if (token) return token;
  } catch {
    // fall through to the plain output
  }
  const raw = wrangler('auth token').trim();
  if (!raw) throw new Error('[migrate-r2-to-kv] no credentials: set CLOUDFLARE_API_TOKEN or run `npx wrangler login`');
  return raw;
}

function resolveAccountId() {
  if (process.env.CLOUDFLARE_ACCOUNT_ID) return process.env.CLOUDFLARE_ACCOUNT_ID;
  const whoami = JSON.parse(wrangler('whoami --json'));
  const accounts = whoami.accounts || [];
  if (accounts.length === 1) return accounts[0].id;
  if (accounts.length > 1) {
    throw new Error(
      '[migrate-r2-to-kv] several accounts available; set CLOUDFLARE_ACCOUNT_ID to one of: ' +
        accounts.map((account) => account.id).join(', ')
    );
  }
  throw new Error('[migrate-r2-to-kv] no account found for these credentials');
}

function resolveNamespaceId(explicit) {
  if (explicit) return explicit;

  const toml = fs.readFileSync(CONFIG, 'utf8');
  const blocks = toml.match(/\[\[kv_namespaces\]\][^[]*/g) || [];
  const block = blocks.find((entry) => /binding\s*=\s*"ATTACHMENTS_KV"/.test(entry));
  const pinned = block && (block.match(/^\s*id\s*=\s*"([^"]+)"/m) || [])[1];
  if (pinned) return pinned;

  const list = JSON.parse(wrangler('kv namespace list'));
  const hit = list.find((namespace) => typeof namespace.title === 'string' && namespace.title.endsWith('attachments-kv'));
  if (hit) return hit.id;
  throw new Error(
    '[migrate-r2-to-kv] no ATTACHMENTS_KV namespace found; run `npm run deploy` once so ensure-kv creates it'
  );
}

async function api(token, pathname, init = {}) {
  const response = await fetch(`${API}${pathname}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init.headers || {}) },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`[migrate-r2-to-kv] ${init.method || 'GET'} ${pathname} failed (${response.status}): ${body.slice(0, 300)}`);
  }
  return response;
}

async function listObjects(token, accountId, bucket, prefix) {
  const objects = [];
  let cursor = '';
  for (;;) {
    const query = new URLSearchParams({ per_page: '1000' });
    if (prefix) query.set('prefix', prefix);
    if (cursor) query.set('cursor', cursor);
    const response = await api(token, `/accounts/${accountId}/r2/buckets/${bucket}/objects?${query}`);
    const body = await response.json();
    objects.push(...(body.result || []));
    cursor = body.result_info?.cursor || '';
    if (!cursor || !body.result_info?.is_truncated) break;
  }
  return objects;
}

async function copyObject(token, accountId, bucket, namespaceId, object) {
  const keyPath = object.key.split('/').map(encodeURIComponent).join('/');
  const response = await api(token, `/accounts/${accountId}/r2/buckets/${bucket}/objects/${keyPath}`);
  const bytes = new Uint8Array(await response.arrayBuffer());

  const metadata = {
    size: bytes.byteLength,
    contentType: object.http_metadata?.contentType || 'application/octet-stream',
    customMetadata: object.custom_metadata || null,
  };

  const form = new FormData();
  form.set('value', new Blob([bytes]), object.key.split('/').pop() || 'blob');
  form.set('metadata', JSON.stringify(metadata));

  const keySegment = object.key.split('/').map(encodeURIComponent).join('/');
  await api(token, `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${keySegment}`, {
    method: 'PUT',
    body: form,
  });

  return bytes.byteLength;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    const source = fs.readFileSync(__filename, 'utf8');
    console.log(source.slice(source.indexOf(' * Usage'), source.indexOf(' */')));
    return;
  }

  if (!options.bucket) throw new Error('[migrate-r2-to-kv] --bucket needs a value');

  const accountId = resolveAccountId();
  const token = resolveToken();
  const namespaceId = resolveNamespaceId(options.namespaceId);

  console.log(`[migrate-r2-to-kv] bucket "${options.bucket}" -> KV namespace ${namespaceId}`);

  const objects = await listObjects(token, accountId, options.bucket, options.prefix);
  if (!objects.length) {
    console.log('[migrate-r2-to-kv] no objects found; nothing to copy');
    return;
  }

  const oversized = objects.filter((object) => Number(object.size) > KV_MAX_OBJECT_BYTES);
  const copyable = objects.filter((object) => Number(object.size) <= KV_MAX_OBJECT_BYTES);

  console.log(`[migrate-r2-to-kv] ${objects.length} object(s): ${copyable.length} to copy, ${oversized.length} over 25 MiB`);

  for (const object of oversized) {
    console.log(`[migrate-r2-to-kv] skip ${object.key} (${object.size} bytes); re-upload it in the client`);
  }

  if (options.dryRun) {
    for (const object of copyable) console.log(`[migrate-r2-to-kv] would copy ${object.key} (${object.size} bytes)`);
    console.log('[migrate-r2-to-kv] dry run, nothing written');
    return;
  }

  let copied = 0;
  let bytes = 0;
  for (const object of copyable) {
    try {
      bytes += await copyObject(token, accountId, options.bucket, namespaceId, object);
      copied += 1;
      console.log(`[migrate-r2-to-kv] copied ${object.key}`);
    } catch (error) {
      console.error(`[migrate-r2-to-kv] failed ${object.key}: ${error.message}`);
    }
  }

  console.log(`[migrate-r2-to-kv] done: ${copied}/${copyable.length} object(s), ${bytes} bytes`);
  if (oversized.length) {
    console.log('[migrate-r2-to-kv] oversized objects still only exist in R2; clients show them as missing');
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
