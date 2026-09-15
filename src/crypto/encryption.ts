const IV_LENGTH = 12;

export async function encryptMessage(plaintext: string, key: CryptoKey): Promise<{ ciphertext: string; nonce: string }> {
  const nonce = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(plaintext));
  return { ciphertext: encode(new Uint8Array(encrypted)), nonce: encode(nonce) };
}

export async function decryptMessage(ciphertext: string, nonce: string, key: CryptoKey): Promise<string> {
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: toArrayBuffer(decode(nonce)) }, key, toArrayBuffer(decode(ciphertext)));
  return new TextDecoder().decode(plaintext);
}

function encode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decode(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
