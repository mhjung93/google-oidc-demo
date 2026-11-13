// 점 검사와 직렬화 — V11(스펙 2026-10-12 §3.1·§5.2).
//
// V10 까지 여기 있던 π_u(시그마 프로토콜)·registrationCommit(cm_u) 는 지웠다: V11 은 등록 때 auid = Poseidon(T_AUID2, s_u) 를
// 내고(D4), 세션마다 Groth16 회로 π_IdP(circuits/pi_idp.circom, lib/mode3_idp_proof.js)로 uid·salt 관계와 세션 바인딩을 보인다(D10).
// 2026-11-13(스펙 2026-11-12 no-pk-u): 요청 서명 메시지 함수 넷(issueRequestMessageV11·registerMessage·slotRequestMessage·revokeSessionMessage)과
// 그 도메인 상수도 지웠다 — 요청은 π_IdP 의 ctx·tag 로 인증한다(lib/mode3_credential.js issueCtx·registerCtx·slotCtx·revokeSessionCtx·tagOf).
import { buildBabyjub } from 'circomlibjs';

let bjP = null;
const getBj = () => (bjP ??= buildBabyjub());

/** 점이 정규 인코딩이고 곡선 위·소수 부분군 안인가. 등록·발급은 되돌릴 수 없어 여기서 걸러낸다(§6.1). */
export async function isValidPoint(o) {
  const bj = await getBj();
  if (typeof o?.x !== 'bigint' || typeof o?.y !== 'bigint') return false;
  const p = bj.F.p;
  if (o.x < 0n || o.x >= p || o.y < 0n || o.y >= p) return false;   // 비정규(non-canonical) 인코딩 거절
  const P = [bj.F.e(o.x), bj.F.e(o.y)];
  return bj.inCurve(P) && bj.inSubgroup(P);
}

// ---- 직렬화 (HTTP 는 bigint 를 못 실으니 10진 문자열) ----
export const pointToStrings = (p) => ({ x: p.x.toString(), y: p.y.toString() });
export const pointFromStrings = (o) => ({ x: BigInt(o.x), y: BigInt(o.y) });
