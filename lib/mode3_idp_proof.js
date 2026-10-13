// π_IdP(스펙 2026-10-12 §4, D10) — 지갑이 세션마다 IdP 에 내는 Groth16. 회로 circuits/pi_idp.circom 과 공개 입력 순서를 공유한다.
// 지갑은 proveIdp 로 만들고, IdP(cia.js)는 **자기가 조립한** 공개 입력(uid 는 요청·계정, auid 는 DB, 나머지는 요청의 점·값)으로 verifyIdp 한다 —
// 지갑이 보낸 publicSignals 를 그대로 검증에 넣으면 아무 auid 에 대한 증명이 통과하므로 그 경로는 두지 않는다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { normalizeAttrs, SCALAR_MAX, MAX_HEIGHT_MAX, PK_I_MAX } from './mode3_credential.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
export const IDP_WASM_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_idp_js', 'pi_idp.wasm');
export const IDP_ZKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_idp_final.zkey');
export const IDP_VKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_idp_vkey.json');

/** circuits/pi_idp.circom 의 component main 공개 입력 순서. tests/test_mode3_artifacts.mjs 가 .sym 과 대조한다. */
export const IDP_PUB_INDEX = Object.freeze({ UID: 0, AUID: 1, AUID_S: 2, C_U_X: 3, C_U_Y: 4, C_S_X: 5, C_S_Y: 6, MAX_HEIGHT: 7, COUNT: 8 });

const isScalar = (v) => typeof v === 'bigint' && v >= 0n && v < SCALAR_MAX;
const isField = (v) => typeof v === 'bigint' && v >= 0n;
const isPt = (p) => isField(p?.x) && isField(p?.y);

/** 공개 입력 8개를 10진 문자열로. IdP 는 여기 넣는 값을 스스로 정한다. */
export function idpPublicSignals({ uid, auid, auid_s, C_u_pt, C_s_pt, max_height }) {
  if (!isScalar(uid)) throw new Error('idpPublicSignals: uid 는 [0, 2^250) bigint');
  if (!isField(auid) || !isField(auid_s)) throw new Error('idpPublicSignals: auid·auid_s(bigint) 가 필요하다');
  if (!isPt(C_u_pt) || !isPt(C_s_pt)) throw new Error('idpPublicSignals: C_u_pt·C_s_pt{x,y}(bigint) 가 필요하다');
  if (typeof max_height !== 'bigint' || max_height < 0n || max_height >= MAX_HEIGHT_MAX) throw new Error('idpPublicSignals: max_height 는 [0, 2^64) bigint');
  return [uid, auid, auid_s, C_u_pt.x, C_u_pt.y, C_s_pt.x, C_s_pt.y, max_height].map(String);
}

/** 증명. 비공개 s_u·blind_u·attrs·arid·r_rp·pk_i·r_s 와 공개 8개. 공개값은 호출자가 같은 비밀로 미리 계산한 것이어야 한다(아니면 witness 실패). */
export async function proveIdp({ uid, s_u, blind_u, attrs, arid, r_rp, pk_i, r_s, auid, auid_s, C_u_pt, C_s_pt, max_height, wasmPath = IDP_WASM_PATH, zkeyPath = IDP_ZKEY_PATH }) {
  for (const [k, v] of [['s_u', s_u], ['blind_u', blind_u], ['arid', arid], ['r_rp', r_rp], ['r_s', r_s]]) if (!isScalar(v)) throw new Error(`proveIdp: ${k} 는 [0, 2^250) bigint`);
  if (typeof pk_i !== 'bigint' || pk_i < 0n || pk_i >= PK_I_MAX) throw new Error('proveIdp: pk_i 는 [0, 2^160) bigint');
  const pub = idpPublicSignals({ uid, auid, auid_s, C_u_pt, C_s_pt, max_height });
  const input = {
    s_u: s_u.toString(), blind_u: blind_u.toString(), attrs: normalizeAttrs(attrs).map(String), arid: arid.toString(), r_rp: r_rp.toString(), pk_i: pk_i.toString(), r_s: r_s.toString(),
    uid: pub[0], auid: pub[1], auid_s: pub[2], C_u_x: pub[3], C_u_y: pub[4], C_s_x: pub[5], C_s_y: pub[6], max_height: pub[7],
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals };
}

/** 검증. publicSignals 는 정규 10진 문자열 8개(lib/mode3_rp.js 의 C-1 과 같은 이유 — 앞자리 0·공백은 받지 않는다). 예외는 false. */
export async function verifyIdp(vkey, publicSignals, proof) {
  if (!Array.isArray(publicSignals) || publicSignals.length !== IDP_PUB_INDEX.COUNT || !publicSignals.every((v) => typeof v === 'string' && /^(0|[1-9][0-9]*)$/.test(v))) return false;
  if (!proof || typeof proof !== 'object') return false;
  try { return await snarkjs.groth16.verify(vkey, publicSignals, proof); } catch { return false; }
}

let vkeyCache = new Map();
/** vkey 파일을 읽어 캐시한다(경로별). 없으면 throw — 호출자(cia.js)가 503 으로 옮긴다. */
export async function loadIdpVkey(p = IDP_VKEY_PATH) {
  if (!vkeyCache.has(p)) vkeyCache.set(p, JSON.parse(await fs.promises.readFile(p, 'utf8')));
  return vkeyCache.get(p);
}
