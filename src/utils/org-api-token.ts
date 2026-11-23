// The access token an organization API key login issues. It names an organization, not a user, so
// AuthService never accepts it, and only POST /api/public/organization/import reads it.
import type { Env } from '../types';
import { getOrganizationApiKey } from '../services/storage-organization-repo';
import { readHmacToken, signHmacToken } from './user-verification-token';

const ORG_API_TOKEN_TYPE = 'nodewarden.org-api.v1';
export const ORG_API_SCOPE = 'api.organization';
export const ORG_API_TOKEN_TTL_SECONDS = 3600;

interface OrgApiTokenPayload {
  typ: typeof ORG_API_TOKEN_TYPE;
  orgId: string;
  /** The key's revision date when the token was issued: rotating the key ends the token. */
  rev: string;
  scope: typeof ORG_API_SCOPE;
  iat: number;
  exp: number;
}

export function createOrgApiToken(env: Env, orgId: string, revisionDate: string): Promise<string> {
  const now = Date.now();
  const payload: OrgApiTokenPayload = {
    typ: ORG_API_TOKEN_TYPE,
    orgId,
    rev: revisionDate,
    scope: ORG_API_SCOPE,
    iat: now,
    exp: now + ORG_API_TOKEN_TTL_SECONDS * 1000,
  };
  return signHmacToken(env, payload);
}

/** The organization id of a valid bearer org token whose key has not been rotated since, or null. */
export async function verifyOrgApiToken(env: Env, authHeader: string | null): Promise<string | null> {
  const [scheme, token, ...rest] = String(authHeader || '').split(' ');
  if (scheme?.toLowerCase() !== 'bearer' || !token || rest.length) return null;
  const payload = await readHmacToken<OrgApiTokenPayload>(env, token);
  if (!payload || payload.typ !== ORG_API_TOKEN_TYPE || payload.scope !== ORG_API_SCOPE) return null;
  if (typeof payload.orgId !== 'string' || !Number.isFinite(payload.exp) || payload.exp < Date.now()) return null;
  const key = await getOrganizationApiKey(env.DB, payload.orgId);
  return key && key.revisionDate === payload.rev ? payload.orgId : null;
}
