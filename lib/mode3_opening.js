// 개봉 요청·결과의 메시지 규약과 서명 — 설계 2026-09-16 §6. 서비스는 secp256k1 서명키(pk_service = 이더리움 주소)로
// EIP-191 personal sign 한다(세션 요청 서명과 같은 스킴). CIA 는 ethers.verifyMessage 로 주소를 복원해 등록부와 대조한다.
// ts 가 메시지에 있어 가로챈 요청을 그대로 재전송해도 5분 뒤엔 죽는다.
import { ethers } from 'ethers';

const dec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);

export function openRequestMessage({ arid, r_s, PPID, D_svc, ts }) {
  return `mode3-open:${arid}:${r_s}:${PPID}:${D_svc.x}:${D_svc.y}:${ts}`;
}
export function openResultMessage(id, ts) {
  return `mode3-open-result:${id}:${ts}`;
}
export function signOpenRequest(wallet, fields) { return wallet.signMessage(openRequestMessage(fields)); }
export function signOpenResult(wallet, id, ts) { return wallet.signMessage(openResultMessage(id, ts)); }

/** 체크섬 주소 또는 null. */
export function recoverSigner(message, sig) {
  try { return ethers.verifyMessage(message, sig); } catch { return null; }
}

/** ts(Unix 초, 10진 문자열)가 now ±skewSec 안인가. */
export function isFreshTs(ts, nowMs = Date.now(), skewSec = 300) {
  if (!dec(ts)) return false;
  const d = Number(ts) - Math.floor(nowMs / 1000);
  return Math.abs(d) <= skewSec;
}
