import { Env } from '../types';

const DEFAULT_CONTENT_TYPE = 'application/octet-stream';

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

export function getBlobStorageKind(env: Env): 'r2' | null {
  return env.ATTACHMENTS ? 'r2' : null;
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
  if (!env.ATTACHMENTS) {
    throw new Error('Attachment storage is not configured');
  }

  await env.ATTACHMENTS.put(key, value, {
    httpMetadata: { contentType: options.contentType || DEFAULT_CONTENT_TYPE },
    customMetadata: options.customMetadata,
  });
}

export async function getBlobObject(env: Env, key: string): Promise<BlobObject | null> {
  if (!env.ATTACHMENTS) return null;

  const object = await env.ATTACHMENTS.get(key);
  if (!object) return null;

  return {
    body: object.body,
    size: Number(object.size) || 0,
    contentType: object.httpMetadata?.contentType || DEFAULT_CONTENT_TYPE,
  };
}

export async function deleteBlobObject(env: Env, key: string): Promise<void> {
  if (!env.ATTACHMENTS) return;
  await env.ATTACHMENTS.delete(key);
}
