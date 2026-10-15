// lib/mode3_oidc_nonce.js — OIDC 래퍼의 순수 유도 함수(스펙 2026-10-16 D3·D4). IdP(cia.js)와 브라우저 사용자 페이지가 같이 쓴다(jose 를 import 하지 않는다 —
// 브라우저 번들은 node:crypto 를 lib/browser/node_crypto.js shim 으로 받는다).
//   uid        = SHA-256(provider|sub) mod 2^250 — 토큰의 iss 는 쓰지 않는다(Google 은 iss 를 두 형태로 낸다).
//   등록 nonce = "reg:" + SHA-256(auid|pk_u.x|pk_u.y) — 토큰을 이 키 재료에 묶는다(가로챈 토큰으로 다른 키를 등록하지 못하게).
//   폐기 nonce = "revoke:" + 32바이트 임의 hex — 등록 토큰과 목적이 섞이지 않게 접두어만 다르다(재사용 = 같은 계정 재폐기, 멱등).
import { createHash, randomBytes } from 'node:crypto';
import { SCALAR_MAX } from './mode3_credential.js';

export const REG_PREFIX = 'reg:';
export const REVOKE_PREFIX = 'revoke:';
const HEX64 = /^[0-9a-f]{64}$/;
const sha256Hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const dec = (v, name) => {
  if (typeof v === 'bigint') { if (v < 0n) throw new Error(`${name}: 음수`); return v.toString(); }
  if (typeof v === 'string' && /^[0-9]+$/.test(v)) return BigInt(v).toString();
  throw new Error(`${name}: 10진 문자열 또는 bigint 가 필요하다`);
};

export function uidOf(provider, sub) {
  if (typeof provider !== 'string' || !provider) throw new Error('uidOf: provider 문자열이 필요하다');
  if (typeof sub !== 'string' || !sub) throw new Error('uidOf: sub 문자열이 필요하다');
  return (BigInt('0x' + sha256Hex(`${provider}|${sub}`)) & (SCALAR_MAX - 1n)).toString();
}
/** 등록 토큰의 nonce — 토큰을 이 공개키에 묶는다(스펙 D4, R-A: auid 는 토큰 발급 전에 알 수 없어 넣지 않는다 — sig_reg 가 결속한다). */
export function regNonce(pk_u) {
  if (!pk_u || typeof pk_u !== 'object') throw new Error('regNonce: pk_u{x,y} 가 필요하다');
  return REG_PREFIX + sha256Hex(`${dec(pk_u.x, 'pk_u.x')}|${dec(pk_u.y, 'pk_u.y')}`);
}
export function newRevokeNonce() { return REVOKE_PREFIX + randomBytes(32).toString('hex'); }
export const isRegNonce = (s) => typeof s === 'string' && s.startsWith(REG_PREFIX) && HEX64.test(s.slice(REG_PREFIX.length));
export const isRevokeNonce = (s) => typeof s === 'string' && s.startsWith(REVOKE_PREFIX) && HEX64.test(s.slice(REVOKE_PREFIX.length));
