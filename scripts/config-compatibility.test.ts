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

test('wrangler.toml is the single config and binds KV attachment storage', () => {
  const config = readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8');

  assert.match(config, /^\[\[kv_namespaces\]\]\n\s*binding = "ATTACHMENTS_KV"$/m);
  assert.doesNotMatch(config, /^\[\[r2_buckets\]\]/m);

  assert.throws(
    () => readFileSync(new URL('../wrangler.kv.toml', import.meta.url), 'utf8'),
    /ENOENT/
  );
});
