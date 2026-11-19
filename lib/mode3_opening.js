// 개봉 요청·결과의 메시지 규약과 서명 — 설계 2026-09-16 §6. RP 는 secp256k1 서명키(pk_service = 이더리움 주소)로
// EIP-191 personal sign 한다(세션 요청 서명과 같은 스킴). IdP 는 ethers.verifyMessage 로 주소를 복원해 등록부와 대조한다.
// ts 가 메시지에 있어 가로챈 요청을 그대로 재전송해도 5분 뒤엔 죽는다.
import { ethers } from 'ethers';

const dec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);

/** 2026-11-19(스펙 trace-without-tag T7): 요청을 특정하는 것은 그 로그인의 auid_s 다(증명의 공개 입력 — 거래에도 있다). 태그의 c1·부분 복호 D_svc 는 없다.
 *  접두어를 바꿔(mode3-open2) 태그 시절의 서명과 섞이지 않게 한다. */
export function openRequestMessage({ arid, PPID, auid_s, ts }) {
  return `mode3-open2:${arid}:${PPID}:${auid_s}:${ts}`;
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
