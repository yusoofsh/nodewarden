#!/usr/bin/env node
/**
 * Make `npm run deploy` work on a fresh account.
 *
 * R2 buckets are referenced by name only, so a deploy against a missing bucket
 * fails. Create the attachments bucket on first deploy and keep the script
 * idempotent for later builds.
 */
const { execSync } = require('node:child_process');

const BUCKET = 'nodewarden-attachments';

const wrangler = (args) =>
  execSync(`npx wrangler ${args}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });

function main() {
  const buckets = JSON.parse(wrangler('r2 bucket list --json'));
  if (buckets.some((bucket) => bucket.name === BUCKET)) {
    console.log(`[ensure-r2] bucket "${BUCKET}" already exists; nothing to do`);
    return;
  }

  wrangler(`r2 bucket create "${BUCKET}"`);
  console.log(`[ensure-r2] created bucket "${BUCKET}"`);
}

main();
