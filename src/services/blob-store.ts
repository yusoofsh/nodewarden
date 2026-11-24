import { Env } from '../types';

const DEFAULT_CONTENT_TYPE = 'application/octet-stream';
export const KV_MAX_OBJECT_BYTES = 25 * 1024 * 1024;

interface KVBlobMetadata {
  size?: number;
  contentType?: string;
  customMetadata?: Record<string, string> | null;
}

export interface BlobObject {
  body: ReadableStream | null;
  size: number;
  contentType: string;
}

export interface PutBlobOptions {
  size: number;
  contentType?: string;
  customMetadata?: Record<string, string>;
}

function hasKvStorage(env: Env): env is Env & { ATTACHMENTS_KV: KVNamespace } {
  return !!env.ATTACHMENTS_KV;
}

export function getBlobStorageKind(env: Env): 'kv' | null {
  return hasKvStorage(env) ? 'kv' : null;
}

export function getBlobStorageMaxBytes(env: Env, configuredLimit: number): number {
  if (!hasKvStorage(env)) return configuredLimit;
  return Math.min(configuredLimit, KV_MAX_OBJECT_BYTES);
}

export function getAttachmentObjectKey(cipherId: string, attachmentId: string): string {
  return `${cipherId}/${attachmentId}`;
}

export function getSendFileObjectKey(sendId: string, fileId: string): string {
  return `sends/${sendId}/${fileId}`;
}

export async function putBlobObject(
  env: Env,
  key: string,
  value: string | ArrayBuffer | ArrayBufferView | ReadableStream,
  options: PutBlobOptions
): Promise<void> {
  if (!hasKvStorage(env)) {
    throw new Error('Attachment storage is not configured');
  }

  if (options.size > KV_MAX_OBJECT_BYTES) {
    throw new Error('KV object too large');
  }

  const metadata: KVBlobMetadata = {
    size: options.size,
    contentType: options.contentType || DEFAULT_CONTENT_TYPE,
    customMetadata: options.customMetadata || null,
  };
  await env.ATTACHMENTS_KV.put(key, value, { metadata });
}

export async function getBlobObject(env: Env, key: string): Promise<BlobObject | null> {
  if (!hasKvStorage(env)) return null;

  const result = await env.ATTACHMENTS_KV.getWithMetadata<KVBlobMetadata>(key, 'arrayBuffer');
  if (!result.value) return null;

  const sizeFromMeta = Number(result.metadata?.size || 0);
  const size = sizeFromMeta > 0 ? sizeFromMeta : result.value.byteLength;

  return {
    body: new Response(result.value).body,
    size,
    contentType: result.metadata?.contentType || DEFAULT_CONTENT_TYPE,
  };
}

export async function deleteBlobObject(env: Env, key: string): Promise<void> {
  if (!hasKvStorage(env)) return;
  await env.ATTACHMENTS_KV.delete(key);
}
