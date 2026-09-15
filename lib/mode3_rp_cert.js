// 서비스 인증서 cert_s — 설계 2026-09-15 §3. RP 가 CIA 에 (name, origin) 으로 등록하면 CIA 가 arid 를 배정하고
// (arid, origin) 에 EdDSA-Poseidon 으로 서명한다. 지갑은 로그인 전에 이 서명을 pk_CIA 로 검증하고, 요청을 보낸
// 오리진과 cert 의 오리진이 같은지 본다 — 피싱 페이지가 진짜 서비스의 arid 를 끼워 넣는 것을 막는다.
// cert_s 는 CIA 에 되돌려 보내지 않는다(13장 unobservability).
import { createHash } from 'node:crypto';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { SCALAR_MAX } from './mode3_credential.js';

export const DOMAIN_MODE3_CERT_S = 365084431357317727016019n;   // ASCII "MODE3CERTS" 빅엔디언

let eddsaP = null, psP = null;
const getEddsa = () => (eddsaP ??= buildEddsa());
const getPs = () => (psP ??= buildPoseidon());

/** origin 문자열 → 250비트 필드 원소. sha256 뒤 상위 비트를 잘라 스칼라 상한 규약에 맞춘다. */
export function originToField(origin) {
  if (typeof origin !== 'string' || origin.length === 0) throw new Error('originToField: origin 문자열이 필요하다');
  const h = createHash('sha256').update(origin, 'utf8').digest('hex');
  return BigInt('0x' + h) & (SCALAR_MAX - 1n);
}

export async function certSMessage(arid, origin) {
  if (typeof arid !== 'bigint' || arid < 0n || arid >= SCALAR_MAX) throw new Error('certSMessage: arid 는 [0, 2^250) bigint');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_CERT_S, arid, originToField(origin)]));
}

export async function signRpCert(prvBuf, { arid, origin }) {
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const s = eddsa.signPoseidon(prvBuf, F.e(await certSMessage(arid, origin)));
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

/** 형식이 깨져도 throw 하지 않고 false — 지갑의 요청 경로에서 그대로 403 으로 이어진다. */
export async function verifyRpCert(pkCIA, { arid, origin, cert }) {
  try {
    if (!cert || typeof cert !== 'object') return false;
    const B = (v) => { if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw new Error('bad'); return BigInt(v); };
    const eddsa = await getEddsa();
    const F = eddsa.F;
    const m = F.e(await certSMessage(arid, origin));
    const sig = { R8: [F.e(B(cert.R8x)), F.e(B(cert.R8y))], S: B(cert.S) };
    const pub = [F.e(BigInt(pkCIA.x)), F.e(BigInt(pkCIA.y))];
    return eddsa.verifyPoseidon(m, sig, pub);
  } catch { return false; }
}

export const certToStrings = (c) => ({ R8x: String(c.R8x), R8y: String(c.R8y), S: String(c.S) });
