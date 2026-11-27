#!/usr/bin/env node
/**
 * Make `npm run deploy` work on a fresh account.
 *
 * R2 buckets are referenced by name only, so a deploy against a missing bucket
 * fails. Create the attachments bucket on first deploy and keep the script
 * idempotent for later builds.
 *
 * `wrangler r2 bucket list` has no JSON output in wrangler 4, so read the plain
 * listing, and treat the API's "already exists" (10004) answer as success.
 * Commands run without a shell so the bucket name is never interpreted.
 */
const { execFileSync } = require('node:child_process');

const BUCKET = 'nodewarden-attachments';

function wrangler(args) {
  try {
    return execFileSync('npx', ['wrangler', ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const stdout = String(error.stdout || '');
    const stderr = String(error.stderr || '');
    const failure = new Error(`wrangler ${args.join(' ')} failed`);
    failure.output = stdout + stderr;
    throw failure;
  }
}

function isListed(listing) {
  return new RegExp(`^name:\\s+${BUCKET.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'm').test(listing);
}

function main() {
  let listing = '';
  try {
    listing = wrangler(['r2', 'bucket', 'list']);
  } catch (error) {
    console.warn(`[ensure-r2] could not list buckets: ${error.output.trim().split('\n')[0] || error.message}`);
  }
  if (isListed(listing)) {
    console.log(`[ensure-r2] bucket "${BUCKET}" already exists; nothing to do`);
    return;
  }

  try {
    wrangler(['r2', 'bucket', 'create', BUCKET]);
    console.log(`[ensure-r2] created bucket "${BUCKET}"`);
  } catch (error) {
    if (/already exists|code: 10004/i.test(error.output || '')) {
      console.log(`[ensure-r2] bucket "${BUCKET}" already exists; nothing to do`);
      return;
    }
    throw error;
  }
}

main();
