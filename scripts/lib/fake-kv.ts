// Minimal KVNamespace stand-in for tests that touch attachment storage.
// Keeps the bytes so uploads can be read back, and records metadata.
export interface FakeKv {
  objects: Map<string, Uint8Array>;
  metadata: Map<string, unknown>;
  put(key: string, value: string | ArrayBuffer | ArrayBufferView | ReadableStream, options?: { metadata?: unknown }): Promise<void>;
  getWithMetadata<T>(key: string, type?: string): Promise<{ value: ArrayBuffer | null; metadata: T | null }>;
  delete(key: string): Promise<void>;
}

export function createFakeKv(): FakeKv {
  const objects = new Map<string, Uint8Array>();
  const metadata = new Map<string, unknown>();
  return {
    objects,
    metadata,
    put: async (key, value, options) => {
      const bytes =
        value instanceof ReadableStream
          ? new Uint8Array(await new Response(value).arrayBuffer())
          : typeof value === 'string'
            ? new TextEncoder().encode(value)
            : ArrayBuffer.isView(value)
              ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice()
              : new Uint8Array(value).slice();
      objects.set(key, bytes);
      if (options?.metadata) metadata.set(key, options.metadata);
    },
    getWithMetadata: async <T>(key: string) => {
      const bytes = objects.get(key);
      if (!bytes) return { value: null, metadata: null };
      return { value: bytes.slice().buffer as ArrayBuffer, metadata: (metadata.get(key) as T) ?? null };
    },
    delete: async (key) => {
      objects.delete(key);
      metadata.delete(key);
    },
  };
}
