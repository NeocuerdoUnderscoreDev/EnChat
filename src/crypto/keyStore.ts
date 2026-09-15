const databaseName = 'enchat-keys';
const storeName = 'private-keys';

type StoredPrivateKey = { userId: string; privateKey: CryptoKey; publicKeyJwk: JsonWebKey };

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(storeName, { keyPath: 'userId' });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Could not open secure key storage.'));
  });
}

export async function getOrCreateUserKey(userId: string): Promise<StoredPrivateKey> {
  const database = await openDatabase();
  const existing = await new Promise<StoredPrivateKey | undefined>((resolve, reject) => {
    const request = database.transaction(storeName, 'readonly').objectStore(storeName).get(userId);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  if (existing) return existing;

  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['encrypt', 'decrypt']);
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const stored = { userId, privateKey: pair.privateKey, publicKeyJwk };
  await new Promise<void>((resolve, reject) => {
    const request = database.transaction(storeName, 'readwrite').objectStore(storeName).put(stored);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
  return stored;
}

export async function generateChatKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function storeChatKey(userId: string, chatId: string, key: CryptoKey): Promise<void> {
  const raw = await crypto.subtle.exportKey('raw', key);
  const database = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = database.transaction(storeName, 'readwrite').objectStore(storeName).put({ userId: `${userId}:${chatId}`, privateKey: key, publicKeyJwk: { raw: toBase64(new Uint8Array(raw)) } });
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function loadChatKey(userId: string, chatId: string): Promise<CryptoKey | null> {
  const database = await openDatabase();
  const record = await new Promise<StoredPrivateKey | undefined>((resolve, reject) => {
    const request = database.transaction(storeName, 'readonly').objectStore(storeName).get(`${userId}:${chatId}`);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return record?.privateKey ?? null;
}

export async function wrapChatKey(chatKey: CryptoKey, publicKeyJwk: JsonWebKey): Promise<string> {
  const publicKey = await crypto.subtle.importKey('jwk', publicKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const raw = await crypto.subtle.exportKey('raw', chatKey);
  return toBase64(new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, raw)));
}

export async function unwrapChatKey(wrappedKey: string, privateKey: CryptoKey): Promise<CryptoKey> {
  const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, toArrayBuffer(fromBase64(wrappedKey)));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
