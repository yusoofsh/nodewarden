import type { Env } from '../types';

/**
 * Account signups, named after Vaultwarden's SIGNUPS_ALLOWED.
 *
 * Unset means allowed: the first account is created freely and later accounts
 * need an invite code. `false`, `0`, `no` or `off` disables registration for
 * every account except the first one on an empty instance, so a deployment can
 * never lock itself out of its own vault.
 */
export function isSignupsAllowed(env: Env): boolean {
  const raw = (env.SIGNUPS_ALLOWED || '').trim().toLowerCase();
  return raw !== 'false' && raw !== '0' && raw !== 'no' && raw !== 'off';
}
