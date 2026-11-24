import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { buildConfigResponse } from '../src/config-response';

test('config enables the official Bitwarden desktop settings dialog', () => {
  const body = buildConfigResponse('https://vault.example.test');

  assert.equal(body.featureStates['desktop-ui-settings-dialog'], true);
  assert.equal(body.environment.vault, 'https://vault.example.test');
  assert.equal(body.object, 'config');
});

test('wrangler.toml is the single config and binds the attachments R2 bucket', () => {
  const config = readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8');

  assert.match(
    config,
    /^\[\[r2_buckets\]\]\nbinding = "ATTACHMENTS"\nbucket_name = "nodewarden-attachments"$/m
  );
  assert.doesNotMatch(config, /^\[\[kv_namespaces\]\]/m);

  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.match(pkg.scripts.deploy, /scripts\/ensure-r2\.cjs/);

  assert.throws(
    () => readFileSync(new URL('../wrangler.kv.toml', import.meta.url), 'utf8'),
    /ENOENT/
  );
});
