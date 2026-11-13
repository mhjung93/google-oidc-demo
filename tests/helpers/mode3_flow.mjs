// V11 흐름 헬퍼(chain 테스트 공용) — 등록된 사용자로 (1) C_u 를 고르고 (2) /cia/issue(π_IdP 포함)를 부르고 (3) π_RP 를 만든다.
// 테스트마다 같은 코드를 적지 않게 한다. 속성은 사용자(테스트)가 정한다(D15) — IdP 는 값을 보지 않으므로 어떤 벡터든 발급된다.
import { randomScalar, registerCtx, slotCtx, revokeSessionCtx } from '../../lib/mode3_credential.js';
import { createSessionKey, buildIssueRequest, buildAuthProof, buildCredentialProof, syncRevocationTree, syncRegistryTree } from '../../lib/mode3_wallet.js';

export const TESTUSER_ATTRS = Object.freeze([1990n, 410n, 0n, 0n, 0n, 0n]);   // testuser(12345) — 지갑 기본 profile { birthYear 1990, country KR } 의 인코딩
export const ALICE_ATTRS = Object.freeze([2005n, 840n, 0n, 0n, 0n, 0n]);      // alice(67890) — { birthYear 2005, country US }

/** registerUser 결과 + attrs → 사용자 묶음 { uid(bigint), s_u, auid, slot, attrs(bigint[]) }. 등록 키는 없다(2026-11-13) — 계정의 비밀은 s_u 하나. */
export function userOf(reg, uid, attrs = TESTUSER_ATTRS) {
  return { uid: BigInt(uid), s_u: reg.s_u, auid: reg.auid, slot: reg.slot, attrs: [...attrs] };
}

// ---- 요청 인증(스펙 2026-11-12 no-pk-u §3.2): 발급이 아닌 요청 셋의 본문. 증명 하나(≈0.3초)씩 든다. ----
/** /cia/register 본문의 지갑 쪽 부분 { auid, n, …π_IdP } — 호출자가 { uid, pwd|code } 또는 { id_token } 을 더한다. reg = { s_u, auid }. */
export async function regBody(reg, uid, { n = randomScalar() } = {}) {
  return { auid: reg.auid.toString(), n: n.toString(), ...(await buildAuthProof({ uid: BigInt(uid), s_u: reg.s_u, ctx: await registerCtx({ n }) })) };
}
/** /cia/slot 본문. user = { uid(bigint), s_u }. */
export async function slotBody(user, nonce = randomScalar()) {
  return { uid: user.uid.toString(), nonce: nonce.toString(), ...(await buildAuthProof({ uid: user.uid, s_u: user.s_u, ctx: await slotCtx({ nonce }) })) };
}
/** /cia/revoke scope=session 본문(사용자 경로). pk_i·sig_i 가 필요하면 호출자가 더한다. */
export async function revokeSessionBody(user, { Cf_s, bound = 0n, nonce = randomScalar() }) {
  return { uid: user.uid.toString(), scope: 'session', Cf_s: String(Cf_s), bound: bound.toString(), nonce: nonce.toString(), ...(await buildAuthProof({ uid: user.uid, s_u: user.s_u, ctx: await revokeSessionCtx({ Cf_s: BigInt(Cf_s), bound, nonce }) })) };
}

/**
 * 세션 발급 한 번. 돌려주는 값 { r, req, session, r_s, r_rp, blind_u, cred } — r 은 CIA 응답, cred = r.body(토큰 묶음).
 * blind_u 를 같은 값으로 다시 주면 같은 C_u(재사용), 새 값이면 새 C_u(CIA 가 슬롯을 갱신·게시). max_height 가 없으면 provider 로 head+300.
 * uidInBody 는 본문의 uid 만 바꾼다(C_u 안의 uid 는 user.uid) — 시연 덮어쓰기 재현용. overrides 는 본문 필드를 덮는다(음성 케이스용).
 * n 은 발급 ctx 의 지갑 난수(2026-11-13) — 안 주면 buildIssueRequest 가 뽑는다. Google 토큰 nonce 를 미리 만든 테스트는 그때 쓴 n 을 준다.
 */
export async function issueV11(cia, user, { arid, chainid = 31337n, allowAgent = 0n, max_height, provider = null, blind_u = randomScalar(), r_s = randomScalar(), r_rp = randomScalar(), session = createSessionKey(), uidInBody = null, overrides = {}, n, post = (p, b) => cia.post(p, b) } = {}) {
  if (max_height === undefined) {
    if (!provider) throw new Error('issueV11: max_height 또는 provider 가 필요하다');
    max_height = BigInt(await provider.getBlockNumber()) + 300n;
  }
  const req = await buildIssueRequest({ uid: user.uid, s_u: user.s_u, blind_u, attrs: user.attrs, arid: BigInt(arid), r_rp, r_s, session, chainid, allowAgent, max_height, ...(n !== undefined ? { n } : {}) });
  if (uidInBody !== null) req.body.uid = String(uidInBody);
  const r = await post('/cia/issue', { ...req.body, ...overrides });
  return { r, req, session, r_s, r_rp, blind_u, cred: r.body, user };
}

/** 발급 결과로 π_RP 를 만든다. tree·registry 를 안 주면 (provider, logAddress) 에서 동기화한다. slot 은 CIA 응답의 슬롯(재발급으로 바뀔 수 있다).
 *  counter(2026-10-22, Task 7): 온체인 execute() 로 직접 보낼 π 는 호출자가 그 거래의 nonce 를 넘겨야 한다(컨트랙트의 pub[33]==nonce 검사) —
 *  안 주면 buildCredentialProof 의 기본값(LOGIN_COUNTER, 로그인·재검증 전용)이 그대로 쓰인다. */
export async function proveV11(issued, { arid, pk_CIA, pk_trace, provider, logAddress, tree, registry, slot = issued.cred?.slot ?? issued.user.slot, disclosure = null, tagR, counter } = {}) {
  const u = issued.user;
  if (!tree) ({ tree } = await syncRevocationTree(provider, logAddress));
  if (!registry) ({ tree: registry } = await syncRegistryTree(provider, logAddress));
  return buildCredentialProof({ uid: u.uid, arid: BigInt(arid), s_u: u.s_u, auid: u.auid, blind_u: issued.blind_u, r_rp: issued.r_rp, r_s: issued.r_s, pk_i: issued.session.pk_i, attrs: u.attrs, credential: issued.cred, pk_CIA, pk_trace, tree, registry, slot, disclosure, ...(tagR !== undefined ? { tagR } : {}), ...(counter !== undefined ? { counter } : {}) });
}
