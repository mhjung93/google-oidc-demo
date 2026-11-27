// mode3/user/idp_return.js — passkey-web 승인 팝업의 zkIdP 인증 창 왕복(스펙 2026-11-17-mode3-passkey-web W5·W6, 계획 Task 6).
// mode3/wallet.html 의 goIdpAuth·takeIdpReturn·readAttrRecord 와 같은 규칙이다. DOM 전역(sessionStorage·localStorage·fetch·location)은 인자로 받는다 —
// 그래서 Node 단위 테스트(tests/test_mode3_user_idp_return.mjs)에서 돈다. 대기 저장분에는 RP 요청(공개값)·발신 오리진·nonce·시각만 둔다 — salt 는 없다.
export const PENDING_KEY = 'mode3.authorize.pending';
export const PENDING_MAX_AGE_MS = 600_000;
export const RECOVER_RESULT_KEY = 'mode3_recover_result';
// 홈의 세션 끝내기(zkWrapper, 2026-11-23) 귀로의 결과 — popup.js 가 남기고 ui.js 가 한 번 보이고 지운다. 토큰은 없다(공개값·사유뿐).
export const WRAP_END_RESULT_KEY = 'mode3_wrap_end_result';
export const WRAP_ACCOUNT_RESULT_KEY = 'mode3_wrap_account_result';   // 2026-11-24: /user 의 "내 계정 폐기" 귀로가 남기는 결과(토큰 없음)
// 2026-11-24(salt 봉투 Task 5): /user 의 백업 더하기·지우기 귀로가 남기는 결과 — 공개값(종류·개수)과 사유뿐이다. 복구 코드·salt·토큰은 없다.
export const WRAP_BACKUP_RESULT_KEY = 'mode3_wrap_backup_result';
export const WRAP_VAULT_RESULT_KEY = 'mode3_wrap_vault_result';   // 2026-11-27: /user "내 속성" 의 되찾기 귀로가 남기는 결과(토큰·속성 값 없음)
export const WRAP_LINK_RESULT_KEY = 'mode3_wrap_link_result';   // 2026-11-26: /user "로그인 계정" 의 더하기·떼기 귀로가 남기는 결과(토큰 없음)

/** zkIdP 인증 창 주소. 성공하면 zkIdP 가 `${walletOrigin}/?authorize=1&idp_nonce=…&idp_code=…` 로 돌려보낸다. purpose 'register' 는 첫 등록·계정 복구. */
export function idpAuthUrl({ ciaUrl, walletOrigin, nonce, purpose = 'issue' }) {
  const u = new URL(`${ciaUrl}/login`);
  u.searchParams.set('nonce', nonce); u.searchParams.set('wallet', walletOrigin); u.searchParams.set('return', '1');
  if (purpose === 'register') u.searchParams.set('purpose', 'register');
  return u.toString();
}

/** zkIdP 로 가기 전에 이어받을 요청을 남긴다(이 오리진·이 창의 sessionStorage). purpose('issue'|'register')를 주면 함께 남겨 돌아온 목적과 대조한다. */
export function savePending(storage, { req, origin, nonce, at, purpose = null }) {
  storage.setItem(PENDING_KEY, JSON.stringify({ req, origin, nonce, at, ...(purpose ? { purpose } : {}) }));
}

const DEC = /^[0-9]+$/;
/** zkIdP 에서 돌아온 길인지 본다. 돌아온 길이 아니면 null, 저장분과 nonce·나이(·남겼으면 목적)가 맞으면 { req, origin, code, purpose, uid, auid }, 어긋나면 { req: null }.
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

/** 같은 오리진 속성 도구(attr.html)의 기록 { auid, s_u, profile } 또는 null. 데모 리셋 표시(/attr/dist/reset.json)의 epoch 가 바뀌었으면 기록을 지우고 null(attr.html 과 같은 규칙).
 *  version 6(2026-11-20 — salt 없음): auid(10진 — 그 salt 의 공개 가명)만 있고 s_u 는 null 이다. 옛 version 4·5(속성 도구를 다시 열기 전의 기록): s_u 가 있고 auid 는 null —
 *  s_u 는 0 < s_u < 2^250 인 10진 문자열이어야 한다. 호출자는 둘 중 있는 쪽으로 "이 기록이 내 salt 의 것인가" 를 대조한다. */
export const ATTR_RECORD_KEY = 'mode3_attr_tool_v1';
/** 속성 기록 version 6 — 속성 도구(attr_page.js)와 같은 칸이다. salt 는 없다. body 는 코어 wrapperAttrRecord 의 응답. */
export const attrRecordOf = (body, at) => ({ version: 6, schema: body.schema, auid: body.auid, profile: body.profile, attrs: body.attrs, commit: body.commit, createdAt: at });
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
  if (v && v.version === 6 && typeof v.auid === 'string' && DEC.test(v.auid) && !('s_u' in v)) return { auid: BigInt(v.auid).toString(), s_u: null, profile };
  const ok = v && (v.version === 5 || v.version === 4) && typeof v.s_u === 'string' && DEC.test(v.s_u) && BigInt(v.s_u) > 0n && BigInt(v.s_u) < (1n << 250n);
  return ok ? { auid: null, s_u: v.s_u, profile } : null;
}

// ---- 패스키 가입의 Google 왕복(스펙 2026-11-20 passkey-google-signup §2) ----
// zkIdP 페이지의 "패스키로 로그인" 이 미등록 브라우저에서 계정을 만들 때, 승인 창이 Google 로 가서 이메일을 확인받고 돌아온다. 가기 전에 남기는 것은
// 공개값뿐이다(uid·등록 증명·로그인 증명·state·시각) — salt 는 없다. 돌아오는 길은 지갑 정적 서버의 /google-relay 가 `/?authorize=1#google_back=1&state=…&id_token=…` 로 넘긴다.
export const SIGNUP_PENDING_KEY = 'mode3.signup.pending';
const b64url = (str) => btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
/** Google 인가 주소와 state. state = "지갑 오리진(base64url).난수" — 중계 화면이 앞부분으로 돌아갈 곳을 고르고, 승인 창이 전체를 저장분과 대조한다. rand 는 테스트용(없으면 16바이트 난수). */
export function googleSignupUrl({ authorizeUrl, clientId, redirectUri, nonce, walletOrigin, rand = null }) {
  const r = rand ?? Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
  const state = `${b64url(walletOrigin)}.${r}`;
  const u = new URL(authorizeUrl);
  for (const [k, v] of Object.entries({ client_id: clientId, response_type: 'id_token', scope: 'openid email', redirect_uri: redirectUri, nonce, state, prompt: 'select_account' })) u.searchParams.set(k, v);
  return { url: u.toString(), state };
}
/** Google 로 가기 전에 이어받을 가입을 남긴다(이 오리진·이 창의 sessionStorage). pend 는 { state, at, idpOrigin, loginNonce, uid, reg, login } — 공개값뿐. */
export function saveSignupPending(storage, pend) { storage.setItem(SIGNUP_PENDING_KEY, JSON.stringify(pend)); }
/** Google 에서 돌아온 길인지 본다(주소의 조각). 아니면 null. 돌아온 길이면 저장분을 늘 지우고, state·나이가 맞으면 { pend, idToken, error }, 어긋나면 { pend: null, idToken: null, error: null }
 *  — 어긋난 길의 토큰은 쓰지 않는다(남이 만든 링크로 남의 Google 계정을 이 패스키에 붙이지 못하게). 주소창 정리는 호출자가 한다. */
export function takeGoogleReturn({ hash, storage, now }) { return takeBack(SIGNUP_PENDING_KEY, { hash, storage, now }); }
/** 두 Google 왕복(가입·래퍼 로그인)이 같이 쓰는 귀환 처리 — key 의 저장분을 꺼내 지우고 state·나이를 대조한다. ok(pend) 는 저장분의 모양 검사(없으면 통과). */
function takeBack(key, { hash, storage, now }, ok = () => true) {
  const f = new URLSearchParams(String(hash ?? '').replace(/^#/, ''));
  if (f.get('google_back') !== '1') return null;
  let pend = null;
  try { pend = JSON.parse(storage.getItem(key) ?? 'null'); } catch { pend = null; }
  storage.removeItem(key);
  const none = { pend: null, idToken: null, error: null };
  if (!pend || typeof pend !== 'object' || typeof pend.state !== 'string' || pend.state !== f.get('state') || typeof pend.at !== 'number' || now - pend.at > PENDING_MAX_AGE_MS || !ok(pend)) return none;
  const idToken = f.get('id_token');
  return { pend, idToken: idToken || null, error: idToken ? null : (f.get('error') || 'no_token') };
}

// ---- 래퍼 로그인의 Google 왕복(스펙 2026-11-20 zkwrapper §2.2, 계획 Task 4) ----
// 서비스의 "zk 로그인" 이 연 승인 창이 Google 로 가서 그 로그인의 ID 토큰(nonce = 요청 키의 해시)을 받아 돌아온다. 가기 전에 남기는 것은 서비스 요청(공개값)·발신 오리진·state·시각뿐이다.
// 요청 키의 개인키는 IndexedDB 에 CryptoKey 로(꺼낼 수 없다), salt 는 어디에도 두지 않는다 — 패스키는 돌아온 뒤에 한 번 묻는다.
export const WRAPPER_PENDING_KEY = 'mode3.wrapper.pending';
/** Google 인가 주소 — googleSignupUrl 과 같다. prompt 는 늘 select_account 다: prompt=none(조용한 발급)은 쓰지 않는다 — 같은 클라이언트 ID 를 쓰는 남의 페이지가 사용자 모르게 토큰을 받는 길을 넓히지 않는다(스펙 §10 C2). */
export function googleAuthUrl({ authorizeUrl, clientId, redirectUri, nonce, walletOrigin, rand = null }) { return googleSignupUrl({ authorizeUrl, clientId, redirectUri, nonce, walletOrigin, rand }); }
/** Google 로 가기 전에 이어받을 로그인을 남긴다(이 오리진·이 창의 sessionStorage). 정해진 칸만 남긴다. */
export function saveWrapperPending(storage, { state, at, req, origin }) { storage.setItem(WRAPPER_PENDING_KEY, JSON.stringify({ state, at, req, origin })); }
/** Google 에서 돌아온 길인지 본다 — takeGoogleReturn 과 같은 규칙(state·10분·1회용). 맞으면 { pend: { state, at, req, origin }, idToken, error }. */
export function takeWrapperReturn({ hash, storage, now }) {
  return takeBack(WRAPPER_PENDING_KEY, { hash, storage, now }, (pend) => Boolean(pend.req) && typeof pend.req === 'object' && typeof pend.origin === 'string');
}
