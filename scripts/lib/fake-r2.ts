// Minimal R2Bucket stand-in for tests that touch attachment storage.
// Keeps the bytes so uploads can be read back.
export interface FakeBucket {
  objects: Map<string, Uint8Array>;
  put(key: string, value: ReadableStream, options?: unknown): Promise<void>;
  get(key: string): Promise<{ body: ReadableStream; size: number; httpMetadata: Record<string, string> } | null>;
  delete(key: string): Promise<void>;
}

export function createFakeBucket(): FakeBucket {
  const objects = new Map<string, Uint8Array>();
  return {
    objects,
    put: async (key, value) => {
      objects.set(key, new Uint8Array(await new Response(value).arrayBuffer()));
    },
    get: async (key) => {
      const bytes = objects.get(key);
      return bytes ? { body: new Response(bytes).body!, size: bytes.length, httpMetadata: {} } : null;
    },
    delete: async (key) => {
      objects.delete(key);
    },
  };
}
