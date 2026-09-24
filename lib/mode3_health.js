// Mode 3 데모 상태 엔드포인트(GET /mode3/health)의 응답 조립 — 설계 2026-09-25 §1. 순수 함수: 서버가 읽은 값을 넣으면 응답 객체.
// 여기 들어가는 값은 화면 상태 패널·체험 모드 판정용이다. uid·PPID·시크릿·키·arid·r_s 는 절대 넣지 않는다(SENSITIVE_KEYS, 단위 테스트).
export const SENSITIVE_KEYS = ['uid', 'PPID', 'secret', 'sk_u', 'pk_u', 'pk_CIA', 'arid', 'r_s'];
const num = (v) => (v === null || v === undefined ? null : Number(v));
export function shortRoot(rootStr) { const s = String(rootStr ?? ''); return s.length > 12 ? `${s.slice(0, 12)}…` : s; }
export function rootAge(head, lastPublished) { if (head === null || head === undefined || lastPublished === null || lastPublished === undefined) return null; return Number(BigInt(head) - BigInt(lastPublished)); }
/** 설정값(끝의 '/' 나 경로가 붙었을 수 있다)에서 origin 만 남긴다 — 주소로 읽히지 않으면 null(허용 목록에서 빠진다). */
export function toOrigin(v) { try { return new URL(String(v)).origin; } catch { return null; } }
/** 허용 목록을 만든다: 비거나 주소가 아닌 항목은 버리고 나머지는 origin 으로 정규화한다. */
export function originList(...vs) { return vs.flat().map(toOrigin).filter(Boolean); }
/** 허용 목록과 정확히 같은 origin 만. 빈 문자열·undefined 항목은 무시(설정이 비어 있어도 "모두 허용"이 되지 않게). */
export function allowOrigin(origin, list) { if (typeof origin !== 'string' || !origin) return false; return (list ?? []).some((o) => typeof o === 'string' && o.length > 0 && o === origin); }
/** 체인 조회에 예산을 씌운다. RPC 가 응답 없이 물고 있으면(ethers 기본 타임아웃 300s) health 핸들러가 그만큼 붙잡힌다.
 *  p 가 먼저 끝나면 타이머를 지운다 — 남겨 두면 이벤트 루프가 그 시간만큼 살아 있다. 시간이 지나면 reject → 호출부의
 *  기존 catch 가 chain: null 로 떨어뜨린다. */
export function bounded(p, ms = 1500) {
  let timer;
  const limit = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('timeout')), ms); });
  return Promise.race([p, limit]).finally(() => clearTimeout(timer));
}
const chainOf = (chain) => (chain ? { id: String(chain.id), head: String(chain.head) } : null);
export function buildAaHealth({ now, chain, root, epoch, lastPublishedBlock, heartbeatBlocks, pendingLeaves, pendingRps, pendingOpenings, accounts, walletOrigin, rpOrigins }) {
  return { role: 'aa', ok: true, now, chain: chainOf(chain), root: shortRoot(root), epoch: num(epoch), lastPublishedBlock: lastPublishedBlock === null || lastPublishedBlock === undefined ? null : String(lastPublishedBlock),
    rootAge: chain ? rootAge(chain.head, lastPublishedBlock) : null, heartbeatBlocks: num(heartbeatBlocks), pendingLeaves: num(pendingLeaves), pendingRps: num(pendingRps), pendingOpenings: num(pendingOpenings), accounts: num(accounts),
    walletOrigin: String(walletOrigin ?? ''), rpOrigins: (rpOrigins ?? []).map(String) };
}
// requests·disclosures(서비스), txs·disclosedTxs(지갑)는 체험 모드의 4·5단계 판정용 **프로세스 안 카운터**다(설계 §3.2).
// 개수만 싣는다 — 무엇을 공개했는지·누가 했는지는 싣지 않는다. 서버를 다시 띄우면 0 부터다.
export function buildRpHealth({ now, chain, status, active, inactiveReason, maxRootAge, rootAge: ra, sessions, requests, disclosures, predicates, walletAgentOrigin, ciaUrl }) {
  return { role: 'rp', ok: true, now, chain: chainOf(chain), status: String(status), active: !!active, inactiveReason: inactiveReason ?? null, maxRootAge: num(maxRootAge), rootAge: num(ra), sessions: num(sessions),
    requests: num(requests ?? 0), disclosures: num(disclosures ?? 0),
    predicates: { countries: num(predicates?.countries ?? 0), minAge: num(predicates?.minAge ?? 0) }, walletAgentOrigin: String(walletAgentOrigin ?? ''), ciaUrl: String(ciaUrl ?? '') };
}
export function buildWalletHealth({ now, chain, secrets, registered, hasCred, sessions, txs, disclosedTxs, ciaReachable, rpOrigin, ciaUrl }) {
  return { role: 'wallet', ok: true, now, chain: chainOf(chain), secrets: String(secrets), registered: !!registered, hasCred: !!hasCred, sessions: num(sessions),
    txs: num(txs ?? 0), disclosedTxs: num(disclosedTxs ?? 0), ciaReachable: !!ciaReachable, rpOrigin: String(rpOrigin ?? ''), ciaUrl: String(ciaUrl ?? '') };
}
/** 응답 헤더: 캐시 금지 + 허용 오리진에만 CORS. express res 를 받는다.
 *  Vary: Origin 은 허용 여부와 무관하게 늘 붙인다 — 응답이 Origin 에 따라 달라진다는 사실 자체는 거절할 때도 참이고,
 *  중간 캐시가 거절 응답을 허용 오리진에 재사용하는 것을 막는다. res.vary() 는 기존 Vary 값을 지우지 않는다. */
export function applyHealthHeaders(req, res, allowList) {
  res.set('Cache-Control', 'no-store');
  res.vary('Origin');
  const origin = req.get('Origin');
  if (allowOrigin(origin, allowList)) res.set('Access-Control-Allow-Origin', origin);
}
