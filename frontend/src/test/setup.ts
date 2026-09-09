import { createHash, randomUUID, webcrypto } from "node:crypto";
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

const mockDigest = vi.fn(
  async (algorithm: AlgorithmIdentifier, data: BufferSource) => {
    const name = typeof algorithm === "string" ? algorithm : algorithm.name;
    if (name.toUpperCase() !== "SHA-256") {
      throw new Error(`${name} is not supported by the test crypto polyfill`);
    }

    const bytes = ArrayBuffer.isView(data)
      ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
      : new Uint8Array(data);
    const digest = createHash("sha256").update(bytes).digest();

    return digest.buffer.slice(
      digest.byteOffset,
      digest.byteOffset + digest.byteLength,
    );
  },
);

const subtle: Record<string, unknown> = {}
for (const key of Object.getOwnPropertyNames(Object.getPrototypeOf(webcrypto.subtle))) {
  const value = (webcrypto.subtle as Record<string, unknown>)[key]
  if (typeof value === 'function') {
    subtle[key] = (value as (...args: unknown[]) => unknown).bind(webcrypto.subtle)
  }
}
subtle.digest = mockDigest;
const asNodeBuffer = (data: BufferSource) =>
  ArrayBuffer.isView(data)
    ? Buffer.from(data.buffer, data.byteOffset, data.byteLength)
    : Buffer.from(new Uint8Array(data));
subtle.sign = (
  algorithm: AlgorithmIdentifier,
  key: CryptoKey,
  data: BufferSource,
) => webcrypto.subtle.sign(algorithm, key, asNodeBuffer(data));
subtle.verify = (
  algorithm: AlgorithmIdentifier,
  key: CryptoKey,
  signature: BufferSource,
  data: BufferSource,
) =>
  webcrypto.subtle.verify(
    algorithm,
    key,
    asNodeBuffer(signature),
    asNodeBuffer(data),
  );

const testCrypto = {
  getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
  randomUUID,
  subtle,
};

Object.defineProperty(globalThis, "crypto", {
  configurable: true,
  value: testCrypto,
});

Object.defineProperty(window, "crypto", {
  configurable: true,
  value: testCrypto,
});

Object.defineProperty(window, "scrollTo", {
  configurable: true,
  value: vi.fn(),
});

afterEach(() => {
  cleanup();
});

class MockStorage implements Storage {
  private store: Record<string, string> = {};
  get length() {
    return Object.keys(this.store).length;
  }
  clear() {
    this.store = {};
  }
  getItem(key: string) {
    return this.store[key] || null;
  }
  setItem(key: string, value: string) {
    this.store[key] = String(value);
  }
  removeItem(key: string) {
    delete this.store[key];
  }
  key(index: number) {
    return Object.keys(this.store)[index] || null;
  }
}

Object.defineProperty(window, "localStorage", {
  value: new MockStorage(),
  configurable: true,
  writable: true,
});

Object.defineProperty(window, "sessionStorage", {
  value: new MockStorage(),
  configurable: true,
  writable: true,
});
