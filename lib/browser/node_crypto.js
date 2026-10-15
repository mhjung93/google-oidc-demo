// lib/browser/node_crypto.js — 브라우저 번들에서 'node:crypto' 자리에 들어가는 shim(계획 R8). 쓰이는 두 함수만 제공한다:
//   randomBytes(n)            lib/mode3_credential.js(randomScalar)·mode3_trace.js·mode3_wallet.js(sk_u)
//   createHash('sha256')      lib/mode3_attr_schema.js(loadSchema 해시, 동기)·lib/mode3_rp_cert.js(originToField, 동기)
// Buffer 는 globalThis.Buffer(Node 는 내장, 브라우저는 lib/browser/globals_shim.js 가 buffer 패키지로 넣는다)를 쓴다.
import { sha256, hexBytes, utf8Bytes } from './sha256.js';

export function randomBytes(n) {
  if (!Number.isInteger(n) || n < 0) throw new Error('randomBytes: 음이 아닌 정수');
  const u8 = new Uint8Array(n);
  if (n > 0) globalThis.crypto.getRandomValues(u8);
  return globalThis.Buffer.from(u8);
}

export function createHash(alg) {
  if (alg !== 'sha256') throw new Error(`createHash shim 은 sha256 만 지원한다: ${alg}`);
  const parts = [];
  const h = {
    update(data, enc = 'utf8') {
      if (typeof data === 'string') parts.push(enc === 'hex' ? hexBytes(data) : utf8Bytes(data));
      else if (data instanceof Uint8Array) parts.push(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
      else throw new Error('createHash shim: 문자열 또는 Uint8Array 만 받는다');
      return h;
    },
    digest(enc) {
      const total = parts.reduce((n, p) => n + p.length, 0);
      const all = new Uint8Array(total);
      let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
      const d = sha256(all);
      return enc === 'hex' ? [...d].map((b) => b.toString(16).padStart(2, '0')).join('') : globalThis.Buffer.from(d);
    },
  };
  return h;
}
export default { randomBytes, createHash };
