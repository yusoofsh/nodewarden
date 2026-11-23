// Drives every Vaultwarden route through this server's real route handlers on an
// in-memory database. A route is handled when a handler answers it (a 404 for the
// sample id still counts), a stub when a catch-all answers with an empty list, refused
// on 405 or 501, and unmatched when no handler claims it.
//
// Usage: tsx --import ./scripts/offline-workers-loader.mjs scripts/parity-audit.ts <vaultwarden-checkout> [--json] [--sso]
// --sso configures an OpenID provider (outbound fetch is stubbed), so the SSO routes, inert by default, are measured as served.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import type { Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { handlePublicRoute } from '../src/router-public';
import { createTestDb } from './lib/d1-sqlite';

const root = process.argv[2];
if (!root) throw new Error('Pass the path of a Vaultwarden checkout');
const asJson = process.argv.includes('--json');
const withSso = process.argv.includes('--sso');
if (withSso) globalThis.fetch = (async () => new Response('{}', { status: 404 })) as typeof fetch;

const SAMPLE = '11111111-2222-3333-4444-555555555555';

function* rustFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) yield* rustFiles(full);
    else if (name.endsWith('.rs')) yield full;
  }
}

interface Route {
  file: string;
  method: string;
  path: string;
}

function readRoutes(): Route[] {
  const apiDir = join(root, 'src/api');
  const routes: Route[] = [];
  for (const file of rustFiles(apiDir)) {
    const rel = relative(apiDir, file);
    if (/^(admin|web|icons|push|notifications|test_seeder)\.rs$/.test(rel)) continue; // other surfaces
    const prefix = rel === 'identity.rs' ? '/identity' : '/api';
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      const m = line.match(/^#\[(get|post|put|delete|patch)\("([^"?]*)/);
      // events.rs mounts its client collect route at /events, outside /api.
      const routePrefix = rel === join('core', 'events.rs') && m?.[2] === '/collect' ? '/events' : prefix;
      if (m) routes.push({ file: rel, method: m[1].toUpperCase(), path: routePrefix + m[2] });
    }
  }
  return routes;
}

type Verdict = 'handled' | 'stub' | 'refused' | 'unmatched';

// The catch-all in router-authenticated.ts that answers every GET with an empty list.
const STUB_PREFIX = /^\/api\/policies(\/|$)/;

async function main() {
  const db = createTestDb();
  await ensureStorageSchema(db);
  const sso = withSso
    ? { SSO_ENABLED: 'true', SSO_AUTHORITY: 'https://sso.example.test', SSO_CLIENT_ID: 'audit', SSO_CLIENT_SECRET: 'audit' }
    : {};
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40), ...sso } as unknown as Env;
  const user = {
    id: SAMPLE, email: 'audit@example.test', name: 'audit', masterPasswordHint: null, masterPasswordHash: 'x', key: '2.a|b|c',
    privateKey: null, publicKey: null, kdfType: 0, kdfIterations: 600000, securityStamp: 's', role: 'admin', status: 'active',
    totpSecret: null, totpRecoveryCode: null, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  } as User;
  await new StorageService(db).createUser(user);

  const rows: Array<Route & { verdict: Verdict; status?: number }> = [];
  for (const route of readRoutes()) {
    const path = route.path.replace(/<[^>]*>/g, SAMPLE);
    const request = () =>
      new Request(`https://audit.test${path}`, {
        method: route.method,
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.1' },
        body: route.method === 'GET' ? undefined : '{}',
      });
    let response: Response | null = null;
    try {
      response = await handlePublicRoute(request(), env, path, route.method, async () => null);
      if (!response) response = await handleAuthenticatedRoute(request(), env, user.id, user, path, route.method);
    } catch {
      response = new Response(null, { status: 500 }); // reached a handler that needed more than an empty request
    }
    if (!response) rows.push({ ...route, verdict: 'unmatched' });
    else if (STUB_PREFIX.test(path)) rows.push({ ...route, verdict: 'stub', status: response.status });
    else if (response.status === 501 || response.status === 405) {
      rows.push({ ...route, verdict: 'refused', status: response.status });
    } else rows.push({ ...route, verdict: 'handled', status: response.status });
  }

  if (asJson) {
    console.log(JSON.stringify(rows, null, 2));
    return;
  }
  const byFile = new Map<string, Record<Verdict, number>>();
  for (const r of rows) {
    const counts = byFile.get(r.file) ?? { handled: 0, stub: 0, refused: 0, unmatched: 0 };
    counts[r.verdict]++;
    byFile.set(r.file, counts);
  }
  console.log('| Vaultwarden file | Handled | Stub | Refused (405/501) | Unmatched |\n|---|---|---|---|---|');
  for (const [file, c] of [...byFile].sort()) console.log(`| ${file} | ${c.handled} | ${c.stub} | ${c.refused} | ${c.unmatched} |`);
  const total = (v: Verdict) => rows.filter((r) => r.verdict === v).length;
  console.log(`\nTotal ${rows.length}: handled ${total('handled')}, stub ${total('stub')}, refused ${total('refused')}, unmatched ${total('unmatched')}`);
}

await main();
