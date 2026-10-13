// V11 흐름 헬퍼(chain 테스트 공용) — 등록된 사용자로 (1) C_u 를 고르고 (2) /cia/issue(π_IdP 포함)를 부르고 (3) π_RP 를 만든다.
// 테스트마다 같은 코드를 적지 않게 한다. 속성은 사용자(테스트)가 정한다(D15) — IdP 는 값을 보지 않으므로 어떤 벡터든 발급된다.
import { randomScalar } from '../../lib/mode3_credential.js';
import { createSessionKey, buildIssueRequest, buildCredentialProof, syncRevocationTree, syncRegistryTree } from '../../lib/mode3_wallet.js';

export const TESTUSER_ATTRS = Object.freeze([1990n, 410n, 0n, 0n, 0n, 0n]);   // testuser(12345) — 지갑 기본 profile { birthYear 1990, country KR } 의 인코딩
export const ALICE_ATTRS = Object.freeze([2005n, 840n, 0n, 0n, 0n, 0n]);      // alice(67890) — { birthYear 2005, country US }

/** registerUser 결과 + attrs → 사용자 묶음 { uid(bigint), s_u, auid, sk_u(hex), slot, attrs(bigint[]) }. */
export function userOf(reg, uid, attrs = TESTUSER_ATTRS) {
  return { uid: BigInt(uid), s_u: reg.s_u, auid: reg.auid, sk_u: reg.sk_u, slot: reg.slot, attrs: [...attrs] };
}

/**
 * 세션 발급 한 번. 돌려주는 값 { r, req, session, r_s, r_rp, blind_u, cred } — r 은 CIA 응답, cred = r.body(토큰 묶음).
 * blind_u 를 같은 값으로 다시 주면 같은 C_u(재사용), 새 값이면 새 C_u(CIA 가 슬롯을 갱신·게시). max_height 가 없으면 provider 로 head+300.
 * uidInBody 는 본문의 uid 만 바꾼다(C_u 안의 uid 는 user.uid) — 시연 덮어쓰기 재현용. overrides 는 본문 필드를 덮는다(음성 케이스용).
 */
export async function issueV11(cia, user, { arid, chainid = 31337n, allowAgent = 0n, max_height, provider = null, blind_u = randomScalar(), r_s = randomScalar(), r_rp = randomScalar(), session = createSessionKey(), uidInBody = null, overrides = {}, post = (p, b) => cia.post(p, b) } = {}) {
  if (max_height === undefined) {
    if (!provider) throw new Error('issueV11: max_height 또는 provider 가 필요하다');
    max_height = BigInt(await provider.getBlockNumber()) + 300n;
  }
  const req = await buildIssueRequest({ uid: user.uid, s_u: user.s_u, blind_u, attrs: user.attrs, arid: BigInt(arid), r_rp, r_s, sk_u: user.sk_u, session, chainid, allowAgent, max_height });
  if (uidInBody !== null) req.body.uid = String(uidInBody);
  const r = await post('/cia/issue', { ...req.body, ...overrides });
  return { r, req, session, r_s, r_rp, blind_u, cred: r.body, user };
}

/** 발급 결과로 π_RP 를 만든다. tree·registry 를 안 주면 (provider, logAddress) 에서 동기화한다. slot 은 CIA 응답의 슬롯(재발급으로 바뀔 수 있다). */
export async function proveV11(issued, { arid, pk_CIA, pk_trace, provider, logAddress, tree, registry, slot = issued.cred?.slot ?? issued.user.slot, disclosure = null, tagR } = {}) {
  const u = issued.user;
  if (!tree) ({ tree } = await syncRevocationTree(provider, logAddress));
  if (!registry) ({ tree: registry } = await syncRegistryTree(provider, logAddress));
  return buildCredentialProof({ uid: u.uid, arid: BigInt(arid), s_u: u.s_u, auid: u.auid, blind_u: issued.blind_u, r_rp: issued.r_rp, r_s: issued.r_s, pk_i: issued.session.pk_i, attrs: u.attrs, credential: issued.cred, pk_CIA, pk_trace, tree, registry, slot, disclosure, ...(tagR !== undefined ? { tagR } : {}) });
}
