// Mode 3 데모 상태 엔드포인트(GET /mode3/health)의 응답 조립 — 설계 2026-09-25 §1. 순수 함수: 서버가 읽은 값을 넣으면 응답 객체.
// 여기 들어가는 값은 화면 상태 패널·체험 모드 판정용이다. uid·PPID·시크릿·키·arid·r_s 는 절대 넣지 않는다(SENSITIVE_KEYS, 단위 테스트).
export const SENSITIVE_KEYS = ['uid', 'PPID', 'secret', 'sk_u', 'pk_u', 'pk_CIA', 'arid', 'r_s'];
const num = (v) => (v === null || v === undefined ? null : Number(v));
export function shortRoot(rootStr) { const s = String(rootStr ?? ''); return s.length > 12 ? `${s.slice(0, 12)}…` : s; }
export function rootAge(head, lastPublished) { if (head === null || head === undefined || lastPublished === null || lastPublished === undefined) return null; return Number(BigInt(head) - BigInt(lastPublished)); }
/** 허용 목록과 정확히 같은 origin 만. 빈 문자열·undefined 항목은 무시(설정이 비어 있어도 "모두 허용"이 되지 않게). */
export function allowOrigin(origin, list) { if (typeof origin !== 'string' || !origin) return false; return (list ?? []).some((o) => typeof o === 'string' && o.length > 0 && o === origin); }
const chainOf = (chain) => (chain ? { id: String(chain.id), head: String(chain.head) } : null);
export function buildAaHealth({ now, chain, root, epoch, lastPublishedBlock, heartbeatBlocks, pendingLeaves, pendingRps, pendingOpenings, accounts, walletOrigin, rpOrigins }) {
  return { role: 'aa', ok: true, now, chain: chainOf(chain), root: shortRoot(root), epoch: num(epoch), lastPublishedBlock: lastPublishedBlock === null || lastPublishedBlock === undefined ? null : String(lastPublishedBlock),
    rootAge: chain ? rootAge(chain.head, lastPublishedBlock) : null, heartbeatBlocks: num(heartbeatBlocks), pendingLeaves: num(pendingLeaves), pendingRps: num(pendingRps), pendingOpenings: num(pendingOpenings), accounts: num(accounts),
    walletOrigin: String(walletOrigin ?? ''), rpOrigins: (rpOrigins ?? []).map(String) };
}
export function buildRpHealth({ now, chain, status, active, inactiveReason, maxRootAge, rootAge: ra, sessions, predicates, walletAgentOrigin, ciaUrl }) {
  return { role: 'rp', ok: true, now, chain: chainOf(chain), status: String(status), active: !!active, inactiveReason: inactiveReason ?? null, maxRootAge: num(maxRootAge), rootAge: num(ra), sessions: num(sessions),
    predicates: { countries: num(predicates?.countries ?? 0), minAge: num(predicates?.minAge ?? 0) }, walletAgentOrigin: String(walletAgentOrigin ?? ''), ciaUrl: String(ciaUrl ?? '') };
}
export function buildWalletHealth({ now, chain, secrets, registered, hasCred, sessions, ciaReachable, rpOrigin, ciaUrl }) {
  return { role: 'wallet', ok: true, now, chain: chainOf(chain), secrets: String(secrets), registered: !!registered, hasCred: !!hasCred, sessions: num(sessions), ciaReachable: !!ciaReachable, rpOrigin: String(rpOrigin ?? ''), ciaUrl: String(ciaUrl ?? '') };
}
/** 응답 헤더: 캐시 금지 + 허용 오리진에만 CORS. express res 를 받는다. */
export function applyHealthHeaders(req, res, allowList) {
  res.set('Cache-Control', 'no-store');
  const origin = req.get('Origin');
  if (allowOrigin(origin, allowList)) { res.set('Access-Control-Allow-Origin', origin); res.set('Vary', 'Origin'); }
}
