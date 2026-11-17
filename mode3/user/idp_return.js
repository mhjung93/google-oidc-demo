// mode3/user/idp_return.js — passkey-web 승인 팝업의 IdP 인증 창 왕복(스펙 2026-11-17-mode3-passkey-web W5·W6, 계획 Task 6).
// mode3/wallet.html 의 goIdpAuth·takeIdpReturn·readAttrRecord 와 같은 규칙이다. DOM 전역(sessionStorage·localStorage·fetch·location)은 인자로 받는다 —
// 그래서 Node 단위 테스트(tests/test_mode3_user_idp_return.mjs)에서 돈다. 대기 저장분에는 RP 요청(공개값)·발신 오리진·nonce·시각만 둔다 — salt 는 없다.
export const PENDING_KEY = 'mode3.authorize.pending';
export const PENDING_MAX_AGE_MS = 600_000;
export const RECOVER_RESULT_KEY = 'mode3_recover_result';

/** IdP 인증 창 주소. 성공하면 IdP 가 `${walletOrigin}/?authorize=1&idp_nonce=…&idp_code=…` 로 돌려보낸다. purpose 'register' 는 첫 등록·계정 복구. */
export function idpAuthUrl({ ciaUrl, walletOrigin, nonce, purpose = 'issue' }) {
  const u = new URL(`${ciaUrl}/login`);
  u.searchParams.set('nonce', nonce); u.searchParams.set('wallet', walletOrigin); u.searchParams.set('return', '1');
  if (purpose === 'register') u.searchParams.set('purpose', 'register');
  return u.toString();
}

/** IdP 로 가기 전에 이어받을 요청을 남긴다(이 오리진·이 창의 sessionStorage). purpose('issue'|'register')를 주면 함께 남겨 돌아온 목적과 대조한다. */
export function savePending(storage, { req, origin, nonce, at, purpose = null }) {
  storage.setItem(PENDING_KEY, JSON.stringify({ req, origin, nonce, at, ...(purpose ? { purpose } : {}) }));
}

const DEC = /^[0-9]+$/;
/** IdP 에서 돌아온 길인지 본다. 돌아온 길이 아니면 null, 저장분과 nonce·나이(·남겼으면 목적)가 맞으면 { req, origin, code, purpose, uid, auid }, 어긋나면 { req: null }.
 *  돌아온 길이면 저장분은 늘 지운다. 주소창 정리(history.replaceState)는 호출자가 한다. */
export function takeIdpReturn({ search, storage, now }) {
  const q = new URLSearchParams(search);
  const code = q.get('idp_code'), nonce = q.get('idp_nonce');
  if (!code && !nonce) return null;
  const purpose = q.get('idp_purpose') === 'register' ? 'register' : 'issue', uid = q.get('idp_uid'), auid = q.get('idp_auid');
  let pend = null;
  try { pend = JSON.parse(storage.getItem(PENDING_KEY) ?? 'null'); } catch { pend = null; }
  storage.removeItem(PENDING_KEY);
  if (!pend || !code || !nonce || pend.nonce !== nonce || typeof pend.at !== 'number' || now - pend.at > PENDING_MAX_AGE_MS) return { req: null };
  if (typeof pend.purpose === 'string' && pend.purpose !== purpose) return { req: null };   // 갈 때의 목적과 돌아온 목적이 다르다(목적을 남기지 않은 옛 대기분은 그대로)
  if (purpose === 'register' && !DEC.test(uid ?? '')) return { req: null };
  return { req: pend.req, origin: pend.origin, code, purpose, uid: purpose === 'register' ? uid : null, auid: purpose === 'register' && DEC.test(auid ?? '') ? auid : null };
}

/** 같은 오리진 속성 도구(attr.html)의 기록 { s_u, profile } 또는 null. 데모 리셋 표시(/attr/dist/reset.json)의 epoch 가 바뀌었으면 기록을 지우고 null(attr.html 과 같은 규칙).
 *  version 5(uid 없음)와 옛 4 를 받고, s_u 는 0 < s_u < 2^250 인 10진 문자열이어야 한다. */
export async function readAttrRecord({ fetch, localStorage }) {
  try {
    const r = await fetch('/attr/dist/reset.json', { cache: 'no-store' });
    if (r.ok) {
      const epoch = String((await r.json()).epoch ?? '');
      if (epoch && localStorage.getItem('mode3_attr_tool_reset') !== epoch) { localStorage.removeItem('mode3_attr_tool_v1'); localStorage.setItem('mode3_attr_tool_reset', epoch); }
    }
  } catch { /* 파일이 없으면(한 머신 데모·테스트) 그대로 */ }
  let v = null;
  try { v = JSON.parse(localStorage.getItem('mode3_attr_tool_v1') ?? 'null'); } catch { v = null; }
  const profile = v?.profile && typeof v.profile === 'object' && !Array.isArray(v.profile) ? v.profile : null;
  const ok = v && (v.version === 5 || v.version === 4) && typeof v.s_u === 'string' && DEC.test(v.s_u) && BigInt(v.s_u) > 0n && BigInt(v.s_u) < (1n << 250n);
  return ok ? { s_u: v.s_u, profile } : null;
}
