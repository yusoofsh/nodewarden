import { parseJson, type AuthedFetch } from './shared';

export const getUserPublicKey = async (authedFetch: AuthedFetch, userId: string): Promise<string> => {
  const response = await authedFetch(`/api/users/${encodeURIComponent(userId)}/public-key`);
  if (!response.ok) throw new Error(`GET public key failed (${response.status})`);
  const body = await parseJson<{ publicKey: string }>(response);
  if (!body) throw new Error('GET public key returned no data');
  return body.publicKey;
};
