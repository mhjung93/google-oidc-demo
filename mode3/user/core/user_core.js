// mode3/user/core/user_core.js — 브라우저 사용자 페이지의 코어(스펙 2026-10-15 §4). mode3_wallet_agent.js 의 라우트 하나하나에 대응하는
// 함수이고 같은 { status, body } 를 돌려준다 — 화면(ui.js·popup.js)이 에이전트 응답을 다루던 코드를 그대로 쓰기 위해서다.
// DOM·fetch 전역에 의존하지 않아 Node 에서도 돈다(tests/test_mode3_user_core.mjs). 비밀은 vault 로만 드나든다.
//
// 저장(kv): registration = 공개 부분만({ uid, auid, pk_u, slot, provider, profile, attrs, userCred:{C_u_pt,Cf_u,issuedAt}|null } — 에이전트 snap 모드의
// stripSecrets 와 같은 경계), secrets = 금고 암호문({ s_u, sk_u, blind_u, sessionKeys: r_s → 세션 개인키 hex }),
// sessions = r_s → 에이전트 세션 레코드에서 sessionPrivKey·witness 를 뺀 것 + origin·account·sessionAddress·proofCache, txs = 기록한 tx 배열,
// demo = 시연 덮어쓰기 1회분. 에이전트와 달리 상태는 kv 가 정본이다 — 읽고 바꾼 뒤 곧바로 다시 쓴다(팝업·다른 탭이 같은 kv 를 본다).
// provider = 'demo'(데모 계정) 또는 IdP 의 OIDC provider(Google 등록, 스펙 2026-10-16). 이 필드가 생기기 전의 registration 에는 없다.
import { ethers } from 'ethers';
import { randomBytes } from 'node:crypto';
import { createVault } from './vault.js';
import { createChain } from './chain.js';
import { createIdp } from './idp.js';
import { encodeProfile, normalizeProfile, assertPredicateTypes, decodeAttrs, schemaInfo } from '../../../lib/mode3_attr_schema.js';
import { createRegistration, eddsaPubOf, createSessionKey, buildIssueRequest, buildCredentialProof, signChallenge, signSessionRequest, signSlotRequest, signRevokeSession, signRegistration, normalizeDisclosure, normalizeSet, disclosureKey, hasPredicate, chooseMaxHeight, ProofCache } from '../../../lib/mode3_wallet.js';
import { sessionLeaf } from '../../../lib/mode3_revocation.js';
import { registryLeaf } from '../../../lib/mode3_registry.js';
import { signPayload, statementDigestFields, proofToCalldata, parseExecuteReceipt, decodeExecuteCalldata, walletAt, walletInterface, FACTORY_ABI, FACTORY_MAX_ROOT_AGE_BAND, FACTORY_MAX_LIFETIME_BAND, PUB_INDEX } from '../../../lib/mode3_onchain.js';
import { SCALAR_MAX, ppid, randomScalar, auidOf } from '../../../lib/mode3_credential.js';
import { verifyRpCert } from '../../../lib/mode3_rp_cert.js';
import { MODE3_ROOTS_ABI } from '../../../lib/mode3_log.js';
import { bounded } from '../../../lib/mode3_health.js';
import { uidOf, regNonce } from '../../../lib/mode3_oidc_nonce.js';

export const USER_STATE_VERSION = 1;
export const DEFAULT_PROFILE = Object.freeze({ birthYear: '1990', country: 'KR' });   // 데모 testuser 기본값(에이전트와 같다). 사용자가 등록 폼에서 바꿀 수 있다.
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
const R = (status, body) => ({ status, body });
const LOCKED = () => R(423, { reason: 'locked' });
const tag = (reason, extra = {}) => Object.assign(new Error(reason), { reason, ...extra });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** id_token(JWT)의 payload 를 서명 검증 없이 읽는다 — uid 선계산용(서명·iss·aud·exp 는 IdP 가 검증한다). 형식이 아니면 던진다. */
const jwtPayload = (t) => {
  const parts = String(t).split('.');
  if (parts.length !== 3) throw tag('oidc_invalid');
  const b = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  const pad = b + '='.repeat((4 - (b.length % 4)) % 4);
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(pad), (c) => c.charCodeAt(0))));
};

export function createUserCore({ kv, config, provider, canonProvider = provider, fetch = globalThis.fetch, fullProve, now = Date.now, log = () => {} }) {
  if (!fullProve?.idp || !fullProve?.cred) throw new Error('createUserCore: fullProve.idp·fullProve.cred 가 필요하다');
  const vault = createVault(kv, { now });
  const chain = createChain({ provider, canonProvider, logAddress: config.logAddress, mirrorAddress: config.mirrorAddress });
  const idp = createIdp({ ciaUrl: config.ciaUrl, fetch, pinnedPk: config.pkCia ?? null, now });
  const TTL = BigInt(config.ttlBlocks ?? 300), GRID = BigInt(config.heightGrid ?? 100);
  if (TTL <= 0n || GRID <= 0n) throw new Error(`ttlBlocks(${TTL})·heightGrid(${GRID}) 는 양수여야 한다`);
  const factoryInterface = new ethers.Interface(FACTORY_ABI);
  let lastSync = null, lastRegistry = null;   // 페이지 수명 메모리(에이전트와 같다)
  // Google 등록의 보류 재료 { s_u, sk_u, pk_u, nonce }(prepareRegistration). 메모리에만 둔다 — 금고 비밀번호 전이라 금고가 없을 수 있다.
  let pendingReg = null;
  /** 세 체인 경로(login·revalidate·tx)의 설정 검사 — 에이전트 chainConfigMissing 의 등가. */
  const chainMissing = () => chain.missing();

  // ---- 저장 도우미 ----
  const getReg = async () => (await kv.get('registration')) ?? null;
  const getSessions = async () => (await kv.get('sessions')) ?? {};
  const putSessions = (s) => kv.set('sessions', s);
  const getTxs = async () => (await kv.get('txs')) ?? [];
  // 바꿀 때마다 kv 에서 새로 읽어 고친 뒤 쓴다 — 한 동작 안의 다른 쓰기(세션키 저장 등)를 옛 사본으로 덮지 않게.
  async function updateReg(fn) { const r = await getReg(); if (!r) return null; fn(r); await kv.set('registration', r); return r; }
  async function updateSessions(fn) { const s = await getSessions(); fn(s); await putSessions(s); }
  async function updateSecrets(fn) { const s = await vault.readSecrets(); s.sessionKeys ??= {}; fn(s); await vault.writeSecrets(s); }
  const sessionKeyOf = async (rsKey) => (await vault.readSecrets()).sessionKeys?.[rsKey] ?? null;
  /** 비밀 공급원(에이전트 SecretSource 의 등가): 공개 registration + 금고의 secrets 를 합친 뷰. 미등록이면 null, 잠겨 있으면 'locked'.
   *  등록 확인이 먼저다 — 미등록 사용자는 금고가 없을 수 있다. */
  async function source() {
    const reg = await getReg(); if (!reg) return null;
    if (!(await vault.key())) return 'locked';
    const sec = await vault.readSecrets();
    return {
      registration: () => ({ uid: reg.uid, s_u: sec.s_u, sk_u: sec.sk_u, attrs: reg.attrs, auid: reg.auid, slot: reg.slot, pk_u: reg.pk_u, profile: reg.profile ?? null }),
      // blind_u 가 금고에 없으면(손상) 자격증명이 없는 것으로 본다 — chooseUserCred 가 새 C_u 를 받는다.
      userCred: () => (reg.userCred && sec.blind_u ? { ...reg.userCred, blind_u: sec.blind_u } : null),
      async setUserCred(uc) {
        reg.userCred = uc ? { C_u_pt: uc.C_u_pt, Cf_u: uc.Cf_u, issuedAt: uc.issuedAt } : null; sec.blind_u = uc ? uc.blind_u : null;
        await updateSecrets((s) => { s.blind_u = sec.blind_u; });
        await updateReg((r) => { r.userCred = reg.userCred; });
      },
      async setSlot(slot) { reg.slot = slot; await updateReg((r) => { r.slot = slot; }); },
    };
  }
  /** 시연 덮어쓰기(에이전트 takeOverride 의 등가) — kv `demo` 의 scope 가 맞을 때만 꺼내고 지운다. 다르면 그대로 둔다. */
  async function takeOverride(scope) { const ov = await kv.get('demo'); if (!ov || ov.scope !== scope) return null; await kv.del('demo'); return ov; }
  /** 세션 전부를 버린다(공개 레코드·π 캐시·세션키). */
  async function dropSessions() { await putSessions({}); await updateSecrets((s) => { s.sessionKeys = {}; }); }
  /** 세션 하나를 버린다 — 에이전트의 `delete state.sessions[rsKey]; cache.deleteSession(rsKey); persist()` 등가(π 캐시는 레코드 안에 있다). */
  async function deleteSession(rsKey) { await updateSessions((s) => { delete s[rsKey]; }); await updateSecrets((s) => { delete s.sessionKeys[rsKey]; }); }
  /** 만료(head > max_height)된 세션을 걷어낸다(설계 §8). 세션의 π 캐시(레코드 안)도 같이 사라진다 — 남겨 두면 같은 r_s 로 다시
   *  로그인했을 때(root 가 그대로면) 옛 세션의 π 가 히트해 새 pk_i·sig 와 어긋난다(2026-09-23 점검 M-1). 세션키도 금고에서 지운다. */
  async function pruneSessions(head) {
    const s = await getSessions(); const gone = [];
    for (const [k, e] of Object.entries(s)) if (BigInt(e.credential.max_height) < head) { delete s[k]; gone.push(k); }
    if (gone.length === 0) return;
    await putSessions(s);
    await updateSecrets((sec) => { for (const k of gone) delete sec.sessionKeys[k]; });
  }
  /** 사용자 자격증명을 바꿔 앉힌다(null 이면 버린다). 옛 자격증명의 세션은 다음 게시에 죽으므로 지금 지우고 증명 캐시도 비운다. */
  async function replaceUserCred(src, userCred) { await src.setUserCred(userCred); await dropSessions(); }
  /** lastSync(status 의 lastRoot·lastRegRoot)에 남길 거울 뷰. 트리는 남기지 않는다(쓰는 곳이 없다). skipSync 는 세션의 proofCache 를 쓴다. */
  const syncSnapshot = (synced) => ({ root: synced.root.toString(), regRoot: synced.regRoot.toString(), epoch: synced.epoch.toString(), head: synced.head.toString(), chainId: synced.chainId.toString(), lastPublishedBlock: synced.mirror.lastPublishedBlock.toString(), canonicalEpoch: synced.canonical.epoch.toString() });
  /** registryCheck 에 넘길 캐노니컬 최신 뷰(V10 — 내 슬롯 확인은 캐노니컬 최신으로). */
  const canonicalView = (synced) => ({ registry: synced.canonical.registry, regRoot: synced.canonical.regRoot, regEpoch: synced.canonical.epoch });
  // d.sel ?? d.setSel: 지갑이 계산한 disclosure 는 {sel,root}, parseExecuteReceipt 가 읽은 온체인 값은 {setSel,setRoot} — 둘 다 받는다.
  const discStrings = (d) => (d ? { mask: d.mask.toString(), lo: d.lo.map(String), hi: d.hi.map(String), set: (d.sel ?? d.setSel ?? 0n) !== 0n ? { sel: (d.sel ?? d.setSel).toString(), root: (d.root ?? d.setRoot).toString() } : null } : null);
  /** 세션 π 캐시 키 — ProofCache.rootKey(chainId, rev, reg) + '|' + discKey. 세션마다 항목 하나(sessions[r_s].proofCache). */
  const proofCacheKey = (chainId, rev, reg, discKey) => `${ProofCache.rootKey(chainId, rev, reg)}|${discKey}`;

  /** 보관 스키마(에이전트 schemaFor 의 등가). hashHint(IdP 응답의 schemaHash)가 보관 해시와 다를 때만 즉시 다시 받는다.
   *  검증 실패 상태면 Error{ reason:'schema_invalid' } — 술어가 있는 요청·등록·속성 저장만 부른다. */
  async function schemaFor(hashHint = null) {
    let s = await idp.schema();
    if (hashHint && hashHint !== s?.hash) s = await idp.schema(true);
    if (idp.schemaInvalid()) throw tag('schema_invalid', { message: `IdP 의 속성 스키마가 검증에 실패했다: ${idp.schemaInvalid()}` });
    if (hashHint && s.hash !== hashHint) log(`[user-core] IdP 응답의 schemaHash(${hashHint})가 보관 스키마(${s.hash})와 다르다`);
    return s;
  }
  /** 등록 응답의 schemaHash 로 보관 스키마를 맞춰 본다. 검증 실패는 이미 기록됐고 등록 자체는 막지 않는다(에이전트 noteSchemaHint). */
  const noteSchemaHint = (hashHint) => schemaFor(hashHint).catch((e) => { if (e.reason !== 'schema_invalid') throw e; });

  // ---- 에이전트 함수의 등가(본문은 mode3_wallet_agent.js 의 같은 이름 함수에서 옮긴다) ----

  /** 에이전트 registryCheck 의 등가. 등록부 확인(설계 §8.2): 내 슬롯의 리프 == Poseidon(auid, Cf_u). 자격증명이 없으면 null.
   *  view 는 { registry, regRoot, regEpoch } — 호출자는 캐노니컬 최신(canonicalView(synced))을 넘긴다. */
  async function registryCheck(view, reg, uc) {
    if (!reg || !Number.isInteger(reg.slot)) return null;
    const leaf = view.registry.leafAt(reg.slot);
    const expected = uc ? await registryLeaf(BigInt(reg.auid), BigInt(uc.Cf_u)) : 0n;
    const r = { slot: reg.slot, leaf: leaf.toString(), expected: expected.toString(), match: uc ? leaf === expected : null, regRoot: view.regRoot.toString(), epoch: view.regEpoch.toString(), checkedAt: new Date(now()).toISOString() };
    lastRegistry = r;
    return r;
  }
  /** 에이전트 mirrorLeafMatches 의 등가. V10(§5): 거울 뷰 등록부의 내 슬롯이 내 자격증명인가. 캐노니컬에는 게시됐어도 거울이 아직
   *  못 따라왔으면 false — 그 상태로는 거울 뷰 트리에서 등록부 증인이 안 만들어진다. 자격증명·슬롯이 없으면 판정 대상이 아니다(true). */
  async function mirrorLeafMatches(synced, reg, uc) {
    if (!uc || !reg || !Number.isInteger(reg.slot)) return true;
    return synced.registry.leafAt(reg.slot) === await registryLeaf(BigInt(reg.auid), BigInt(uc.Cf_u));
  }
  /** 에이전트 chooseUserCred 의 등가(snap 분기 없음). 들고 있는 C_u 가 등록부에서 내 슬롯에 살아 있으면 재사용(blind_u 그대로),
   *  없거나 은퇴(슬롯 0)면 새 blind_u. 남의 리프면 registry_mismatch — IdP 의 부정(또는 내가 모르는 재발급).
   *  돌려주는 값: { blind_u, fresh } 또는 { status:403, reason, registry? }. */
  async function chooseUserCred(synced, src) {
    const reg = src.registration();
    const uc = src.userCred();
    if (!uc) return { blind_u: randomScalar(), fresh: true };
    const chk = await registryCheck(canonicalView(synced), reg, uc);   // V10: 캐노니컬 최신 — 은퇴·바꿔치기를 거울보다 먼저 안다
    if (!chk) return { status: 403, reason: 'registry_slot_unknown' };
    if (chk.match) return { blind_u: BigInt(uc.blind_u), fresh: false };
    if (chk.leaf !== '0') return { status: 403, reason: 'registry_mismatch', registry: chk };
    return { blind_u: randomScalar(), fresh: true };   // 슬롯 0: 은퇴됐다 — 새로 받는다
  }
  /** 에이전트 checkService 의 등가 — login·precheck 가 같이 쓴다. 통과면 null, 아니면 { status, body }.
   *  cert_s 가 pk_CIA 서명이어야 하고(오리진은 호출자가 대조한다), 팩토리는 인증서의 arid·pk_trace, 고정된 pk_CIA·거울 주소와 온체인 값이
   *  같아야 한다(2026-09-18 점검 3). 팩토리·검증자 코드의 참조 빌드 대조(verifyReferenceCode)는 하지 않는다 — 스펙 2026-10-15 §6:
   *  브라우저에는 참조 아티팩트가 없고, web 모드에서는 팩토리 코드 대조를 RP 의 책임으로 두고 한계에 적는다. */
  async function checkService({ arid, origin, cert_s, pk_trace, factoryAddress }) {
    // IdP 가 죽어 pk_CIA 를 못 받은 것이지 체인 문제가 아니다 — reason 목록엔 없지만 원인을 구분해 둔다.
    let pk;
    try { pk = await idp.pkCia(); } catch (e) { return R(503, { reason: 'cia_unavailable', detail: e.message }); }
    if (!(await verifyRpCert(pk, { arid: BigInt(arid), origin, pk_trace, cert: cert_s }))) return R(403, { reason: 'bad_rp_cert' });
    if (factoryAddress !== null) {
      try {
        const f = chain.factory(factoryAddress);
        const [fa, fl, fx, fy, tx, ty, fra, flt] = await Promise.all([f.arid(), f.log(), f.pkCIAX(), f.pkCIAY(), f.pkTraceX(), f.pkTraceY(), f.maxRootAge(), f.maxLifetime()]);
        // V10(2026-10-02 §5): 계정 컨트랙트는 대상 체인의 거울을 읽는다 — 팩토리의 log() 는 캐노니컬이 아니라 거울이어야 한다.
        if (fa !== BigInt(arid) || fl.toLowerCase() !== config.mirrorAddress.toLowerCase() || fx !== pk.x || fy !== pk.y || tx !== BigInt(pk_trace.x) || ty !== BigInt(pk_trace.y)) {
          return R(409, { reason: 'bad_factory' });
        }
        // 상한 두 개도 본다(2026-09-25 리뷰 I-3): 너무 크면 AA 가 게시를 멈춰도 온체인 실행이 계속되고(폐기 신선도 상실), 0 이면 그 계정의
        // 모든 execute 가 revert 해 이미 넣은 자산이 영구 동결된다(주소가 이 인자들로 결정돼 다른 값으로 재배포할 수 없다).
        if (BigInt(fra) < FACTORY_MAX_ROOT_AGE_BAND.min || BigInt(fra) > FACTORY_MAX_ROOT_AGE_BAND.max) return R(409, { reason: 'bad_factory', detail: 'maxRootAge out of band' });
        if (BigInt(flt) < FACTORY_MAX_LIFETIME_BAND.min || BigInt(flt) > FACTORY_MAX_LIFETIME_BAND.max) return R(409, { reason: 'bad_factory', detail: 'maxLifetime out of band' });
      } catch (e) { return R(409, { reason: 'bad_factory', detail: e.shortMessage ?? e.message }); }
    }
    return null;
  }
  /** 에이전트 issueSession 의 등가. 세션 발급(V11 §5.2): C_u(blind_u)·C_s·π_IdP 를 한 요청으로. 200 이면 세션을 저장하고, 새 C_u 였으면
   *  사용자 자격증명도 바꿔 앉힌다(옛 세션은 함께 버린다). π_IdP 는 주입된 fullProve.idp 로 만든다(브라우저는 워커 프록시, 계획 R7).
   *  세션 개인키는 금고(secrets.sessionKeys[r_s])에만, 공개 레코드에는 origin·account(PPID 계정 주소)·sessionAddress 를 함께 둔다. */
  async function issueSession({ arid, r_s, r_rp, pk_trace, allowAgent, factoryAddress, attrGateAddress, head, src, blind_u, origin }) {
    const reg = src.registration();
    const session = createSessionKey();
    const chainid = await chain.chainId();
    const ov = await takeOverride('issue');   // 시연(설계 §8.3): 이번 발급의 s_u·uid 를 한 번만 덮어쓴다 — 가짜 auid 로 증명돼 IdP 가 bad_idp_proof 를 낸다
    const req = await buildIssueRequest({
      uid: BigInt(ov?.uid ?? reg.uid), s_u: BigInt(ov?.s_u ?? reg.s_u), blind_u, attrs: (reg.attrs ?? []).map(BigInt), arid: BigInt(arid), r_rp, r_s,
      sk_u: reg.sk_u, session, chainid, allowAgent: BigInt(allowAgent), max_height: chooseMaxHeight(head, { ttlBlocks: TTL, grid: GRID }), fullProve: fullProve.idp,
    });
    if (ov?.uid) req.body.uid = reg.uid;   // 요청 본문의 uid 는 진짜 — C_u·π_IdP 안의 uid 만 바뀐다(스펙 §8.3)
    const r = await idp.post('/cia/issue', req.body);
    if (r.status !== 200) return { r, demo: ov ? 'override:issue' : undefined };
    // V10(§4.5): 계정 폐기로 슬롯이 은퇴된 뒤 되살아난 계정의 재발급은 새 슬롯을 받는다 — 응답의 슬롯을 따른다.
    if (Number.isInteger(r.body?.slot) && r.body.slot >= 0 && r.body.slot !== reg.slot) await src.setSlot(r.body.slot);
    const uc = src.userCred();
    if (!uc || uc.Cf_u !== req.Cf_u.toString()) await replaceUserCred(src, { C_u_pt: { x: req.C_u_pt.x.toString(), y: req.C_u_pt.y.toString() }, Cf_u: req.Cf_u.toString(), blind_u: blind_u.toString(), issuedAt: new Date(now()).toISOString() });
    const PPID = await ppid({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u), arid: BigInt(arid), chainid });
    const rsKey = r_s.toString();
    const account = factoryAddress ? await chain.accountAddressOf(factoryAddress, PPID.toString()) : null;
    // 개인키를 먼저 금고에 넣고 공개 레코드를 쓴다 — 레코드가 있는데 키가 없는 순간을 만들지 않는다.
    await updateSecrets((s) => { s.sessionKeys[rsKey] = session.wallet.privateKey; });
    await updateSessions((all) => {
      all[rsKey] = {
        arid, PPID: PPID.toString(), pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, factoryAddress, attrGateAddress, allowAgent,
        r_rp: r_rp.toString(), auid_s: req.auid_s.toString(), arid_s: req.arid_s.toString(),
        credential: r.body, pk_i: session.pk_i.toString(), issuedAt: new Date(now()).toISOString(),
        // 이 세션이 어느 RP 오리진의 것인지 남긴다(2026-09-25 리뷰 D-4) — 세션 경로가 요청 오리진과 대조한다. 호출자가 인증서와 대조를 마친 값이다.
        origin, account, sessionAddress: session.wallet.address, proofCache: null,
      };
    });
    return { r, demo: ov ? 'override:issue' : undefined };
  }
  /** 에이전트 proveSession 의 등가. 세션의 성명으로 현재 (revRoot, regRoot) 에 대한 π 를 만든다(캐시, disclosure 별 — 세션마다 항목 하나).
   *  V9: 사용자 자격증명의 활성 여부는 등록부로 본다 — 내 슬롯이 내 자격증명이 아니면 throw('revoked'). V8: 세션 리프가 폐기 트리에 있으면
   *  throw('revoked_session'). 세션이 없으면 throw('no_session'). 시연 덮어쓰기(scope='prove')가 걸려 있으면 증명 실패를
   *  throw('demo_proof_failed') 로. disclosure 가 없으면(mask 0) 기본 π. 증명은 주입된 fullProve.cred 로 만든다. */
  async function proveSession(rsKey, synced, timings, disclosure = null, src) {
    const s = (await getSessions())[rsKey];
    if (!s) throw tag('no_session');
    const priv = await sessionKeyOf(rsKey);
    if (!priv) throw tag('no_session');   // 금고에 세션키가 없으면 이 세션으로는 서명할 수 없다 — 없는 세션과 같이 다룬다
    const reg = src.registration();
    const uc = src.userCred();
    const sessionWallet = new ethers.Wallet(priv);
    const discKey = hasPredicate(disclosure) ? disclosureKey(disclosure) : '0';
    // V10(2026-10-02): 폐기 사전 확인은 캐시 히트여도 한다. 캐시 키는 거울 뷰 (root, regRoot) 인데, 거울이 뒤처진 동안 캐노니컬에서
    // 폐기·은퇴가 일어나면 키가 그대로라 히트가 나고, 미스일 때만 보면 이미 아는 폐기를 놓친 채 옛 π 를 계속 낸다. 확인은 해시 두어 번이라 싸다.
    // 세션이 물린 사용자 자격증명 위에 발급된 경우(동시 로그인 경합으로 그 사이 새 C_u 를 받았다) — 지금 C_u 의 blind_u 로는 증명이
    // 안 만들어진다. 그 세션은 다음 게시에 어차피 죽으므로 revoked 로 정리한다.
    if (s.credential.Cf_u !== uc?.Cf_u) throw tag('revoked');
    const chk = await registryCheck(canonicalView(synced), reg, uc);   // V10: 캐노니컬 최신으로 — π 는 아래에서 거울 뷰 트리로 만든다
    if (!chk) throw tag('registry_slot_unknown');
    if (!chk.match) throw tag('revoked', { registry: chk });
    // V8: 세션 리프. V10: 캐노니컬 최신 트리로 본다 — 거울이 아직 그 폐기를 싣지 않았어도 폐기된 세션을 더 쓰지 않는다.
    if (synced.canonical.tree.has(await sessionLeaf(BigInt(s.credential.Cf_s)))) throw tag('revoked_session');
    const key = proofCacheKey(synced.chainId, synced.root, synced.regRoot, discKey);
    const pc = s.proofCache;
    let cached = pc && pc.key === key ? { proof: pc.proof, publicSignals: pc.publicSignals, revRoot: BigInt(pc.revRoot), regRoot: BigInt(pc.regRoot) } : null;
    const cacheHit = Boolean(cached);
    if (!cached) {
      // V10: 캐노니컬에서는 내 슬롯이 맞지만 거울이 아직 못 따라왔다 — 거울 뷰로는 증명이 안 된다. 세션은 그대로 두고 503 으로(릴레이 뒤 다시).
      if (!(await mirrorLeafMatches(synced, reg, uc))) throw tag('registry_unpublished');
      const t = now();
      const ov = await takeOverride('prove');   // 시연(설계 §8.3): 다음 증명의 s_u·uid 를 한 번만 바꿔치기
      const prove = async (tree, registry) => {
        try {
          return await buildCredentialProof({
            uid: BigInt(ov?.uid ?? reg.uid), arid: BigInt(s.arid), s_u: BigInt(ov?.s_u ?? reg.s_u), auid: BigInt(reg.auid), blind_u: BigInt(uc.blind_u),
            r_rp: BigInt(s.r_rp), r_s: BigInt(rsKey), pk_i: BigInt(s.pk_i), attrs: (reg.attrs ?? []).map(BigInt),
            credential: s.credential, pk_CIA: { x: BigInt(s.credential.pk_CIA.x), y: BigInt(s.credential.pk_CIA.y) },
            pk_trace: { x: BigInt(s.pk_trace.x), y: BigInt(s.pk_trace.y) }, tree, registry, slot: reg.slot, disclosure, fullProve: fullProve.cred,
          });
        } catch (e) {
          // 시연 덮어쓰기가 걸려 있었다면 원인은 거의 항상 그것이다(가짜 s_u·uid 로는 witness 가 안 만들어진다) — 500 대신 호출자가 409 로 보여준다.
          if (ov) throw tag('demo_proof_failed', { detail: e.message });
          // 사전 검사와 증인 생성 사이에 내 세션 리프가 붙으면 getNonMembershipWitness 가 "… is a member …" 로 던진다(lib/imt_v2.js).
          if (/is a member/.test(e.message ?? '')) throw tag('revoked_session');
          throw e;
        }
      };
      cached = await prove(synced.tree, synced.registry);
      // V10: π 는 반드시 거울의 (revRoot, regRoot) 를 실어야 한다 — RP·계정 컨트랙트는 거울만 읽는다. 어긋나면 거울 epoch 시점의
      // 격리 트리(untilEpoch 재생)로 한 번만 다시 증명하고, 그래도 다르면 sync_unstable 로 끝낸다(에이전트와 같다 — 이 코어는 트리를
      // 공유하지 않아 보통은 일어나지 않는다).
      if (cached.revRoot !== synced.root || cached.regRoot !== synced.regRoot) {
        try {
          const t2 = await chain.replayAt(synced.epoch, synced.root, synced.regRoot);
          cached = await prove(t2.tree, t2.registry);
        } catch (e) {
          // 재생 root 불일치는 미태그 Error 라 그대로 두면 호출자의 503 매핑을 빠져나가 500 이 된다 — 사유가 없는 오류만 sync_unstable 로 태그한다.
          if (e.reason) throw e;
          throw tag('sync_unstable', { detail: e.message });
        }
        if (cached.revRoot !== synced.root || cached.regRoot !== synced.regRoot) throw tag('sync_unstable');
      }
      timings.proveMs = now() - t;
      const entry = { key: proofCacheKey(synced.chainId, cached.revRoot, cached.regRoot, discKey), proof: cached.proof, publicSignals: cached.publicSignals, revRoot: cached.revRoot.toString(), regRoot: cached.regRoot.toString() };
      await updateSessions((all) => { if (all[rsKey]) all[rsKey].proofCache = entry; });
    }
    const root = (cached.revRoot ?? synced.root).toString();
    const regRoot = (cached.regRoot ?? synced.regRoot).toString();
    const sig = await signChallenge(sessionWallet, rsKey);
    // 시연(가짜 증명, 사용자 요청 2026-10-14): pi_a·pi_c 를 바꿔친다 — 둘 다 유효한 G1 점이라 형식은 그대로지만 페어링이 깨져 RP(bad_proof)·
    // 체인(InvalidProof) 모두 거절한다. 캐시가 쥔 원본은 손대지 않는다 — 복사본(얕은 복제) 쪽만 맞바꾼다. 원본을 고치면 이 세션의 다음
    // (정상) 요청까지 가짜 증명을 받는다.
    const fakeProof = await takeOverride('fake_proof');
    const proof = fakeProof ? { ...cached.proof, pi_a: cached.proof.pi_c, pi_c: cached.proof.pi_a } : cached.proof;
    return { proof, publicSignals: cached.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root, regRoot, cacheHit, allowAgent: s.allowAgent, max_height: s.credential.max_height, ...(fakeProof ? { demo: 'override:fake_proof' } : {}) };
  }
  /** 에이전트 sessionMatchesRequester 의 등가(origin 은 Origin 헤더 자리). 남의 RP 세션은 "없는 것"과 같이 다룬다. 있는 단서는 전부 본다:
   *  요청 오리진과 세션 오리진이 둘 다 있으면 같아야 하고, arid 가 있으면 세션 arid 와 같아야 한다. */
  const sessionMatches = (s, origin, arid) => !(origin && s.origin && origin !== s.origin) && (arid === undefined || arid === null || String(arid) === String(s.arid));
  /** proveSession 이 던진 사유 → 응답(revalidate·prepareTx 공통). revoked·revoked_session 은 그 세션을 지운다. 모르는 사유는 null. */
  async function sessionProofFailure(e, rsKey, timings) {
    // 그 세션만 지운다. 사용자 자격증명은 그대로 둔다 — 다음 로그인의 chooseUserCred 가 등록부로 알아채 새로 받는다.
    if (e.reason === 'revoked') { await deleteSession(rsKey); return R(403, { reason: 'revoked', registry: e.registry, timings }); }
    // V8: 이 세션 하나만 폐기됐다 — 지우는 범위는 같지만(그 세션) 사유가 다르다.
    if (e.reason === 'revoked_session') { await deleteSession(rsKey); return R(403, { reason: 'revoked_session', timings }); }
    if (e.reason === 'demo_proof_failed') return R(409, { reason: e.reason, detail: e.detail, demo: 'override:prove', timings });
    if (e.reason === 'registry_slot_unknown') return R(403, { reason: 'registry_slot_unknown', timings });
    if (e.reason === 'registry_unpublished') return R(503, { reason: 'registry_unpublished', timings });
    if (e.reason === 'sync_unstable') return R(503, { reason: 'chain_unavailable', detail: e.message, timings });
    return null;
  }

  /** 등록 공통부 — 에이전트 POST /wallet/register(file 모드 규칙)의 등가 + 금고, + OIDC 분기(스펙 2026-10-16 §3.1). register(데모 계정)와
   *  completeRegistration(Google)이 같이 쓴다. V11 §3.1·§3.3 — 등록 키(sk_u/pk_u)·salt(s_u) 는 지갑이 만들고(reg) auid = Poseidon(T_AUID, uid, s_u)
   *  를 IdP 에 낸다. 속성은 사용자가 넣는다(D15): profile(기본 DEFAULT_PROFILE)을 공개 스키마로 인코딩해 attrs 를 만든다 — IdP 는 받지 않는다.
   *  금고가 없으면 vaultPassword 로 만들고(IdP 호출 직전), 있으면 잠금 해제 상태여야 한다. kv 에는 공개 부분(registration)만 평문으로,
   *  s_u·sk_u 는 금고(secrets)에만 둔다. auth 는 IdP 인증({ uid, pwd } 또는 { id_token }) — 요청 본문에 그대로 펼친다.
   *  provider 는 IdP 응답에 provider 가 없을 때 registration 에 남길 값이다. */
  async function registerWith({ uid, auth, reg, profileIn, vaultPassword, provider }) {
    if (profileIn !== null && (typeof profileIn !== 'object' || Array.isArray(profileIn))) return R(400, { reason: 'bad_attr', detail: 'profile_required' });
    const existing = await getReg();
    if (existing) return R(409, { reason: 'already_registered', uid: existing.uid });
    await vault.refresh();
    const needSetup = !vault.hasVault();
    const hasVaultPw = typeof vaultPassword === 'string' && vaultPassword.length > 0;
    if (needSetup && !hasVaultPw) return R(400, { error: 'vaultPassword 필요(금고가 아직 없다)' });
    // 금고가 이미 있으면 절대 다시 만들지 않고, 비밀번호가 함께 왔으면 **그 비밀번호로 연다**(맞지 않으면 IdP 호출 전에 400 bad_password).
    // 복구 시나리오: 첫 등록이 IdP 401(IdP 비밀번호 오타) 등으로 실패하면 금고(비밀번호 A)만 남고 30분 동안 해제돼 있다. 재시도에서 사용자가
    // 금고 비밀번호를 B 로 넣었는데 조용히 무시하고 A 의 키로 s_u·sk_u 를 암호화하면, 30분 뒤 B 로는 열리지 않고(A 가 오타였다면 영구히)
    // IdP 쪽은 이미 등록돼 있어 wipe 후 재등록도 409 다. 잠긴 금고에 비밀번호를 함께 보낸 경우도 같은 규칙으로 연다. 비밀번호 없이 잠겨 있으면 423.
    if (!needSetup) {
      if (hasVaultPw) { if (!(await vault.unlock(vaultPassword))) return R(400, { reason: 'bad_password' }); }
      else if (!(await vault.key())) return LOCKED();
    }
    let schema;
    try { schema = (await schemaFor()).schema; } catch (e) { if (e.reason === 'schema_invalid') return R(503, { reason: 'schema_invalid', detail: e.message }); throw e; }
    // profile 을 안 보냈을 때만 DEFAULT_PROFILE 을 스키마의 슬롯 이름으로 거른다 — IdP 가 country 같은 이름을 빼면 encodeProfile 이
    // 그 키를 unknown_field 로 거절하므로, 기본값은 "그 스키마가 아는 이름"만 남긴다. 사용자가 직접 보낸 profile 은 그대로 둔다.
    const profile = profileIn ?? Object.fromEntries(Object.entries(DEFAULT_PROFILE).filter(([k]) => schema.slots.some((s) => s.type !== 'unused' && s.name === k)));
    let attrs;
    try { attrs = await encodeProfile(schema, profile, { allowEmptyRequired: false }); }
    catch (e) { if (e.reason === 'bad_attr') return R(400, { reason: 'bad_attr', slot: e.slot, field: e.field, detail: e.detail, message: e.message }); throw e; }
    const normalized = normalizeProfile(schema, profile);
    // 금고는 IdP 에 등록하기 **전에** 만든다 — 등록이 끝났는데 비밀을 둘 곳이 없는 상태(재로그인 불가)를 만들지 않는다.
    if (needSetup) await vault.setup(vaultPassword);
    const pub = { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() };
    const r = await idp.post('/cia/register', { ...auth, auid: reg.auid.toString(), pk_u: pub, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), reg.auid) });
    if (r.status !== 201) {
      // OIDC 사유(oidc_disabled·oidc_invalid·oidc_nonce_mismatch·oidc_unavailable)는 그 사유·상태 그대로 — 화면이 원인을 나눠 보여준다.
      if (typeof r.body?.reason === 'string' && r.body.reason.startsWith('oidc_')) return R(r.status, { reason: r.body.reason, cia: r.body });
      const status = r.status === 401 || r.status === 409 ? r.status : 502;
      return R(status, { reason: 'register_failed', cia: r.body });
    }
    await noteSchemaHint(r.body.schemaHash ?? null);
    // 비밀을 먼저 금고에 쓰고 공개 부분을 쓴다 — registration 이 있으면 비밀도 있다.
    await vault.writeSecrets({ s_u: reg.s_u.toString(), sk_u: reg.sk_u, blind_u: null, sessionKeys: {} });
    // uid 는 지갑이 auid 에 넣은 값이다 — 201 이면 IdP 가 sig_reg 를 자기 uid 로 검증했으므로 응답의 uid 와 같다.
    const savedProvider = r.body.provider ?? provider;
    await kv.set('registration', { uid, auid: reg.auid.toString(), pk_u: pub, slot: r.body.slot, provider: savedProvider, profile: normalized, attrs, userCred: null });
    await putSessions({});
    const body = { uid, slot: r.body.slot, auid: reg.auid.toString(), attrs, profile: normalized };
    // provider 는 OIDC 경로의 응답에만 싣는다 — 데모 register 의 응답 키는 그대로 둔다(데모 쪽은 status().provider 로 본다).
    return R(201, 'id_token' in auth ? { ...body, provider: savedProvider } : body);
  }

  // ---- 동작(에이전트 라우트의 등가) ----
  const ops = {
    /** 에이전트 GET /wallet/status 의 등가(sync:true = ?sync=1). 비밀 없음 — 세션의 sessionAddress 는 레코드에 저장해 둔 값이다. rcl 은 null(R2). */
    async status({ sync = false } = {}) {
      await vault.refresh();
      let head = null;
      try { head = (await provider.getBlockNumber()).toString(); } catch { /* 체인 없음 */ }
      const reg = await getReg();
      // 새로고침 버튼(sync=1, V9 §8.2): 강제로 다시 동기화해 등록부 확인 줄(lastRegistry)을 갱신한다. 실패해도 응답은 지금까지의 값으로 낸다.
      if (sync && config.logAddress && reg) {
        try { const synced = await chain.syncAll(); await registryCheck(canonicalView(synced), reg, reg.userCred); } catch { /* 체인 없음 */ }
      }
      // V10(§5): 대상 체인 거울과 캐노니컬 로그의 지금 값. 읽지 못하면 null — 상태 응답 자체는 그대로 낸다.
      let mirrorStatus = { address: config.mirrorAddress ?? null, epoch: null, lastPublishedBlock: null };
      if (config.mirrorAddress) {
        try { const m = new ethers.Contract(config.mirrorAddress, MODE3_ROOTS_ABI, provider); const [e, l] = await bounded(Promise.all([m.epoch(), m.lastPublishedBlock()]), 1200); mirrorStatus = { address: config.mirrorAddress, epoch: e.toString(), lastPublishedBlock: l.toString() }; } catch { /* 못 읽음 */ }
      }
      let canonicalEpoch = null;
      if (config.logAddress) { try { canonicalEpoch = (await bounded(new ethers.Contract(config.logAddress, MODE3_ROOTS_ABI, canonProvider).epoch(), 1200)).toString(); } catch { /* 못 읽음 */ } }
      const sessions = {};
      for (const [r_s, e] of Object.entries(await getSessions())) {
        // 세션의 PPID 계정 주소(CREATE2 라 배포 전에도 정해진다). 로그인 때 못 구했으면(RPC 실패) 여기서 다시 묻는다(캐시).
        const account = e.account ?? (e.factoryAddress ? await chain.accountAddressOf(e.factoryAddress, e.PPID) : null);
        sessions[r_s] = { account, arid: e.arid, PPID: e.PPID, max_height: e.credential.max_height, chainid: e.credential.chainid, allowAgent: e.allowAgent, factoryAddress: e.factoryAddress, attrGateAddress: e.attrGateAddress ?? null, sessionAddress: e.sessionAddress ?? null, issuedAt: e.issuedAt, pk_trace: e.pk_trace };
      }
      // userCred.revoked 는 마지막 등록부 확인(lastRegistry)으로 판정한다(여기서 다시 확인하지 않는다, V9 §8.2). 아직 확인이 없으면 null.
      const uc = reg?.userCred ?? null;
      const userCred = uc ? { Cf_u: uc.Cf_u, issuedAt: uc.issuedAt, revoked: lastRegistry ? !lastRegistry.match : null } : null;
      const sch = await idp.schema();
      const ov = await kv.get('demo');
      return R(200, {
        registered: Boolean(reg), uid: reg?.uid ?? null, provider: reg?.provider ?? null, auid: reg?.auid ?? null, slot: reg?.slot ?? null, attrs: reg?.attrs ?? null, userCred, sessions,
        profile: reg?.profile ?? null, attrSchema: sch ? schemaInfo(sch.schema, sch.hash) : null,
        attrsView: reg && sch ? decodeAttrs(sch.schema, reg.attrs, reg.profile ?? null) : null,
        registry: lastRegistry, demoOverride: ov ? { scope: ov.scope, fields: Object.keys(ov).filter((k) => k !== 'scope') } : null,
        head, lastRoot: lastSync?.root ?? null, lastRegRoot: lastSync?.regRoot ?? null, logAddress: config.logAddress ?? null, ciaUrl: config.ciaUrl,
        mirror: mirrorStatus, canonical: { rpc: config.revRpcUrl ?? config.rpcUrl ?? null, logAddress: config.logAddress ?? null, epoch: canonicalEpoch },
        rcl: null,
      });
    },
    /** 에이전트 GET /wallet/attr_schema 의 등가 — 지갑 화면이 이름 ↔ 코드를 바꾸는 데 쓰는 전체 스키마. */
    async attrSchema() {
      try { const s = await schemaFor(); return R(200, { schema: s.schema, hash: s.hash, source: s.source }); }
      catch (e) { if (e.reason === 'schema_invalid') return R(503, { reason: 'schema_invalid', detail: e.message }); throw e; }
    },
    /** 에이전트 POST /wallet/register(file 모드 규칙)의 등가 + 금고 — 데모 계정(uid·pwd) 경로. 규칙은 registerWith 에 있다. */
    async register({ uid, pwd, profile: profileIn = null, vaultPassword = null } = {}) {
      if (!isDec(uid) || typeof pwd !== 'string') return R(400, { error: 'uid(10진 문자열), pwd 필요' });
      if (BigInt(uid) >= SCALAR_MAX) return R(400, { error: 'uid 는 2^250 미만' });
      return registerWith({ uid, auth: { uid, pwd }, reg: await createRegistration(BigInt(uid)), profileIn, vaultPassword, provider: 'demo' });
    },
    /** Google(OIDC) 등록 2단계(스펙 2026-10-16 §3.1): 토큰의 sub 로 uid = uidOf(provider, sub) 를 선계산하고(서명은 IdP 가 검증한다)
     *  보류 재료로 auid 를 만들어 registerWith 로 낸다 — IdP 에는 { id_token, auid, pk_u, sig_reg }. 보류 재료는 성공해야 비운다(실패하면
     *  같은 재료·nonce 로 다시 시도할 수 있다). 토큰은 IdP 요청 본문에만 싣고 저장·기록하지 않는다. */
    async completeRegistration({ idToken, profile: profileIn = null, vaultPassword = null } = {}) {
      const existing = await getReg();
      if (existing) return R(409, { reason: 'already_registered', uid: existing.uid });   // 토큰·보류 재료보다 먼저(registerWith 도 다시 본다)
      const pend = pendingReg;
      if (!pend) return R(409, { reason: 'no_pending_registration' });
      if (typeof idToken !== 'string' || !idToken) return R(400, { error: 'idToken(문자열) 필요' });
      let claims;
      try { claims = jwtPayload(idToken); } catch { return R(400, { reason: 'oidc_invalid', detail: 'id_token 형식이 아니다' }); }
      if (typeof claims?.sub !== 'string' || !claims.sub || typeof claims.nonce !== 'string') return R(400, { reason: 'oidc_invalid', detail: 'sub·nonce 가 없다' });
      if (claims.nonce !== pend.nonce) return R(400, { reason: 'oidc_nonce_mismatch' });
      let keys;
      try { keys = await idp.publicKeys(); } catch (e) { return R(502, { reason: 'cia_unavailable', detail: e.message }); }
      if (keys.status !== 200) return R(502, { reason: 'cia_unavailable', detail: `public_keys HTTP ${keys.status}` });
      const oidc = keys.body?.oidc;
      if (!oidc?.enabled || typeof oidc.provider !== 'string' || !oidc.provider) return R(503, { reason: 'oidc_disabled' });
      const uid = uidOf(oidc.provider, claims.sub);
      const reg = { s_u: pend.s_u, sk_u: pend.sk_u, pk_u: pend.pk_u, auid: await auidOf({ uid: BigInt(uid), s_u: pend.s_u }) };
      const r = await registerWith({ uid, auth: { id_token: idToken }, reg, profileIn, vaultPassword, provider: oidc.provider });
      if (r.status === 201 && pendingReg === pend) pendingReg = null;   // 그 사이 다시 prepare 했으면 새 재료는 남긴다
      return r;
    },
    /** 에이전트 PUT /wallet/profile 의 등가. V11 §3.3 — 스키마 검증 → attrs 재인코딩 → 바뀌었으면 옛 C_u·세션·π 캐시를 버린다(다음 로그인이
     *  새 C_u 를 발급받는다 — PPID 는 그대로). 바뀌면 금고의 blind_u·세션키도 지우므로 잠겨 있으면 423(아무것도 바꾸기 전에). */
    async saveProfile(profile) {
      const reg = await getReg();
      if (!reg) return R(409, { reason: 'not_registered' });
      if (!profile || typeof profile !== 'object' || Array.isArray(profile)) return R(400, { reason: 'bad_attr', detail: 'profile_required' });
      let schema;
      try { schema = (await schemaFor()).schema; } catch (e) { if (e.reason === 'schema_invalid') return R(503, { reason: 'schema_invalid', detail: e.message }); throw e; }
      let attrs;
      try { attrs = await encodeProfile(schema, profile, { allowEmptyRequired: false }); }
      catch (e) { if (e.reason === 'bad_attr') return R(400, { reason: 'bad_attr', slot: e.slot, field: e.field, detail: e.detail, message: e.message }); throw e; }
      const normalized = normalizeProfile(schema, profile);
      const changed = JSON.stringify(attrs) !== JSON.stringify(reg.attrs ?? []);
      if (changed && !(await vault.key())) return LOCKED();
      if (changed) { await updateSecrets((s) => { s.blind_u = null; s.sessionKeys = {}; }); await putSessions({}); }
      await updateReg((r) => { r.profile = normalized; if (changed) { r.attrs = attrs; r.userCred = null; } });
      return R(200, { attrs, profile: normalized, changed });
    },
    /** 에이전트 POST /wallet/authorize/precheck 의 등가 — 팝업이 동의 화면을 띄우기 전에 인증서·팩토리를 검사한다. 오리진 대조는 여기서
     *  하지 않는다: 팝업이 postMessage 의 event.origin 으로 확인한 값을 login 의 verifiedOrigin 으로 낸다. 비밀이 필요 없다. */
    async precheck(body) {
      const { arid, origin, cert_s, pk_trace, factoryAddress = null, r_s = null } = body ?? {};
      if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !pk_trace || !isDec(pk_trace.x) || !isDec(pk_trace.y)) return R(400, { error: 'arid, origin, cert_s, pk_trace{x,y} 필요' });
      if (factoryAddress !== null && !isAddr(factoryAddress)) return R(400, { error: 'factoryAddress 는 주소' });
      if (chainMissing()) return R(503, { reason: 'chain_unavailable', detail: chainMissing() });
      const bad = await checkService({ arid, origin, cert_s, pk_trace, factoryAddress });
      if (bad) return bad;
      // 재승인(r_s 있음): 동의 창의 "AI 에이전트 허용" 은 RP 가 보낸 값이 아니라 **이 세션의 실제 값**이어야 한다(2026-09-23 점검 B-I1).
      // 인증서 검사를 통과한 뒤에만 답한다 — 남의 오리진이 세션의 allowAgent 를 물어볼 수 없다.
      if (r_s !== null) {
        if (!isDec(r_s)) return R(400, { error: 'r_s 는 10진 문자열' });
        const s = (await getSessions())[BigInt(r_s).toString()];
        // 남의 RP 세션은 없는 것과 같이 다룬다 — 유효한 인증서를 가진 RP A 가 RP B 세션의 r_s 로 A 의 이름이 적힌 동의 창을 띄우지 못하게 한다.
        if (!s || String(s.arid) !== String(arid)) return R(404, { reason: 'no_session' });
        return R(200, { ok: true, sessionAllowAgent: String(s.allowAgent) });
      }
      return R(200, { ok: true });
    },
    /** 에이전트 POST /wallet/login 의 등가. 오리진은 snap 모드 규칙 — 팝업이 postMessage 의 event.origin 으로 확인한 verifiedOrigin 을
     *  인증서 오리진(body.origin)과 대조한다(피싱 페이지는 인증서의 오리진에서 메시지를 보낼 수 없다). 비밀은 금고에서(witness 없음).
     *  사유·상태 코드·검사 순서는 에이전트와 같다. 성공 본문에는 비밀·uid 가 없다. */
    async login(body, { verifiedOrigin = null } = {}) {
      const { arid, origin, cert_s, pk_trace, r_s, r_rp, allowAgent = '0', factoryAddress = null, attrGateAddress = null, disclose = null, set = null } = body ?? {};
      if (!isDec(arid) || typeof origin !== 'string' || !cert_s || !pk_trace || !isDec(pk_trace.x) || !isDec(pk_trace.y) || !isDec(r_s) || !isDec(r_rp)) return R(400, { error: 'arid, origin, cert_s, pk_trace{x,y}, r_s, r_rp 필요' });
      if (allowAgent !== '0' && allowAgent !== '1') return R(400, { error: 'allowAgent 는 "0" 또는 "1"' });
      if (factoryAddress !== null && !isAddr(factoryAddress)) return R(400, { error: 'factoryAddress 는 주소' });
      // attrGateAddress 는 RP 가 알려주는 값을 세션에 실어 나를 뿐 지갑이 검증하지 않는다(스펙 §6.1) — 지갑 폼 기본값(to)으로만 쓰인다.
      if (attrGateAddress !== null && !isAddr(attrGateAddress)) return R(400, { error: 'attrGateAddress 는 주소' });
      const pubReg = await getReg();
      if (!pubReg) return R(409, { reason: 'not_registered' });
      if (chainMissing()) return R(503, { reason: 'chain_unavailable', detail: chainMissing() });
      const rs = BigInt(r_s), rrp = BigInt(r_rp);
      if (rs >= SCALAR_MAX || rrp >= SCALAR_MAX) return R(400, { error: 'r_s·r_rp 는 2^250 미만' });
      // r_s 는 세션 식별자다 — 같은 값으로 두 번 로그인할 정당한 경로가 없고, 덮어쓰면 캐시의 옛 π 와 새 세션키가 어긋난다.
      if ((await getSessions())[rs.toString()]) return R(409, { reason: 'duplicate_session' });
      // V7: 로그인 성명에도 술어를 실을 수 있다(스펙 §6). 형식·불만족은 체인 작업 전에 걸러낸다(attrs 는 공개 부분).
      let disclosure = null;
      if (disclose || set) {
        try { assertPredicateTypes((await schemaFor()).schema, disclose, set); }
        catch (e) {
          if (e.reason === 'schema_invalid') return R(503, { reason: 'schema_invalid', detail: e.message });
          if (e.reason === 'predicate_type') return R(400, { reason: 'predicate_type', detail: e.message });
          throw e;
        }
        try { const attrs = (pubReg.attrs ?? []).map(BigInt); disclosure = { ...normalizeDisclosure(disclose, attrs), ...(await normalizeSet(set, attrs)) }; }
        catch (e) { if (e.reason) return R(400, { reason: e.reason, detail: e.message }); throw e; }
      }
      // RP 인증(설계 §3·§4): cert_s 가 pk_CIA 서명이고, 요청을 보낸 오리진이 cert 의 오리진과 같아야 한다.
      // pk_trace 는 인증서가 덮는다 — RP 가 자기만 아는 키를 주면 RP 혼자 태그를 연다(2026-09-16 §2).
      if (verifiedOrigin !== origin) return R(403, { reason: 'bad_rp_cert' });
      const bad = await checkService({ arid, origin, cert_s, pk_trace, factoryAddress });
      if (bad) return bad;

      // 비밀이 처음 필요한 자리 — 에이전트의 secretSourceFor 위치. 잠겨 있으면 여기서 423(인증서·팩토리 검사는 비밀 없이 끝났다).
      const src = await source();
      if (src === null) return R(409, { reason: 'not_registered' });
      if (src === 'locked') return LOCKED();
      // V9: 옛 등록(슬롯 없음)은 IdP 의 /cia/slot 으로 되찾는다.
      const reg = src.registration();
      if (reg.slot === null || reg.slot === undefined) {
        const nonce = randomScalar();
        const r0 = await idp.post('/cia/slot', { uid: reg.uid, nonce: nonce.toString(), sig_u: await signSlotRequest(reg.sk_u, BigInt(reg.uid), nonce) });
        // 슬롯은 음이 아닌 정수여야 한다(리뷰 Minor 1) — IdP 가 망가진 값을 주면 registryCheck 가 영구히 null 을 돌려주게 된다.
        if (r0.status !== 200 || !Number.isInteger(r0.body?.slot) || r0.body.slot < 0) return R(502, { reason: 'slot_failed', cia: r0.body });
        await src.setSlot(r0.body.slot);
      }
      const timings = { syncMs: 0, userCredMs: 0, issueMs: 0, proveMs: 0 };
      let t = now();
      let synced;
      try { synced = await chain.syncAll(); }
      catch (e) { return R(503, { reason: 'chain_unavailable', detail: e.message }); }
      timings.syncMs = now() - t;
      lastSync = syncSnapshot(synced);

      await pruneSessions(synced.head);
      // V11: 사용자 자격증명은 발급 요청에 함께 실려 간다 — 들고 있는 C_u 를 재사용할지(등록부에 살아 있음) 새로 만들지(없음·은퇴)를 먼저 정한다.
      const pick = await chooseUserCred(synced, src);
      if (pick.status === 403) return R(403, { reason: pick.reason, ...(pick.registry ? { registry: pick.registry } : {}), timings });
      const issueArgs = { arid, r_s: rs, r_rp: rrp, pk_trace: { x: BigInt(pk_trace.x), y: BigInt(pk_trace.y) }, allowAgent, factoryAddress: factoryAddress ? ethers.getAddress(factoryAddress) : null, attrGateAddress: attrGateAddress ? ethers.getAddress(attrGateAddress) : null, head: synced.head, src, origin };
      t = now();
      const issued = await issueSession({ ...issueArgs, blind_u: pick.blind_u });
      timings.issueMs = now() - t;
      timings.userCredMs = pick.fresh ? timings.issueMs : 0;   // 새 C_u 를 받은 로그인만 0 이 아니다(테스트·화면이 본다)
      let r = issued.r, demo = issued.demo;
      // V10 no_user_cred 재시도의 V11 등가물: IdP 가 "이미 물린 C_u" 라며 거절하면(경합 등) 버리고 새 C_u 로 한 번만 다시 시도한다.
      if (r.status === 409 && r.body?.reason === 'cred_revoked') {
        await replaceUserCred(src, null);
        t = now();
        const retried = await issueSession({ ...issueArgs, blind_u: randomScalar() });
        const retryMs = now() - t;
        timings.issueMs += retryMs;
        timings.userCredMs = retryMs;
        r = retried.r; demo = retried.demo;
      }
      if (r.status === 403) return R(403, { reason: 'account_disabled', timings });
      if (r.status === 400 && r.body?.reason === 'bad_idp_proof') return R(502, { reason: 'user_cred_failed', cia: r.body, ...(demo ? { demo } : {}), timings });
      if (r.status !== 200) return R(502, { reason: 'issue_failed', cia: r.body, ...(demo ? { demo } : {}), timings });
      // 방금 새 사용자 자격증명을 받았으면(fresh) 그 슬롯이 등록부에 게시될 때까지 기다린다 — 안 그러면 바로 이어지는 proveSession 이
      // 아직 옛(또는 빈) 슬롯을 보고 죽는다(2026-10-01 §8.3). V10: π 는 거울 뷰로 만들고 RP 도 거울을 읽으므로 **거울의 regRoot 가 내 리프를
      // 담을 때까지** 기다린다. fresh 가 아니어도 거울 뷰에 내 리프가 없으면(관리자 바꿔치기를 되돌린 직후 등) 같은 이유로 기다린다.
      if (pick.fresh || !(await mirrorLeafMatches(synced, src.registration(), src.userCred()))) {
        const deadline = now() + 30_000;
        for (;;) {
          // 다른 동기화 호출부와 같은 모양으로 감싼다 — 일시적 RPC 오류가 세션이 저장된 뒤에 분류 안 된 500 이 되지 않게.
          try { synced = await chain.syncAll(); }
          catch (e) { return R(503, { reason: 'chain_unavailable', detail: e.message }); }
          lastSync = syncSnapshot(synced);
          const chk = await registryCheck(canonicalView(synced), src.registration(), src.userCred());
          if (!chk) return R(403, { reason: 'registry_slot_unknown', timings });
          if (chk.match && synced.registry.leafAt(chk.slot).toString() === chk.expected) break;   // 캐노니컬에 있고 거울 뷰에도 반영됐다
          if (now() > deadline) return R(503, { reason: 'registry_unpublished', registry: chk, timings });
          await sleep(2000);
        }
      }
      let out;
      try { out = await proveSession(rs.toString(), synced, timings, disclosure, src); }
      catch (e) {
        if (e.reason === 'no_session') return R(409, { reason: 'no_session', timings });
        if (e.reason === 'demo_proof_failed') return R(409, { reason: e.reason, detail: e.detail, demo: 'override:prove', timings });
        if (e.reason === 'registry_slot_unknown') return R(403, { reason: 'registry_slot_unknown', timings });
        if (e.reason === 'registry_unpublished') return R(503, { reason: 'registry_unpublished', timings });
        if (e.reason === 'sync_unstable') return R(503, { reason: 'chain_unavailable', detail: e.message, timings });
        throw e;
      }
      // 시연(가짜 서명, 사용자 요청 2026-10-14): 세션키 대신 매번 새로 뽑는 임의 키로 서명한다 — RP 의 verifyLogin 이 복원한 주소가 pk_i 와
      // 달라 bad_signature 로 거절한다. tx 경로는 prepareTx 의 signPayload 호출부에서 따로 takeOverride 한다.
      const fakeSig = await takeOverride('fake_sig');
      if (fakeSig) out = { ...out, sig: await signChallenge(ethers.Wallet.createRandom(), rs.toString()), demo: 'override:fake_sig' };
      return R(200, { ...out, issued: true, allowAgent, timings, disclosure: hasPredicate(disclosure) ? discStrings(disclosure) : null });
    },
    /** 에이전트 POST /wallet/revalidate 의 등가(origin 은 Origin 헤더 자리 — 팝업이 event.origin 을 넘긴다). */
    async revalidate({ r_s, skipSync = false, arid = null, origin = null } = {}) {
      if (!isDec(r_s)) return R(400, { error: 'r_s 필요' });
      const rsKey = BigInt(r_s).toString();
      const s = (await getSessions())[rsKey];
      if (!s || !sessionMatches(s, origin, arid)) return R(404, { reason: 'no_session' });
      if (chainMissing()) return R(503, { reason: 'chain_unavailable', detail: chainMissing() });
      // 세션키·비밀이 필요하다 — 동기화(전체 재생) 전에 잠김을 본다.
      const src = await source();
      if (src === null) return R(409, { reason: 'not_registered' });
      if (src === 'locked') return LOCKED();
      const timings = { syncMs: 0, issueMs: 0, proveMs: 0 };
      // 시연용: 동기화를 건너뛰고 이 세션의 마지막 π 를 그 (revRoot, regRoot) 그대로 재제출한다(RP 의 stale_root/stale_registry_root 거절을 보이기 위해).
      // 에이전트는 프로세스 메모리의 lastSync 로 캐시 항목을 찾았지만, web 모드에서는 RP 동작마다 새 팝업 페이지가 열려 lastSync 가 늘 비어 있다 —
      // 그래서 kv(IndexedDB)에 남은 세션의 proofCache 를 쓴다. 세션마다 항목이 하나라 마지막 π 가 술어 π(tx 의 선택 공개)일 수도 있다.
      if (skipSync) {
        const pc = s.proofCache;
        if (!pc) return R(409, { reason: 'no_cached_proof' });
        const priv = await sessionKeyOf(rsKey);
        if (!priv) return R(404, { reason: 'no_session' });
        const sig = await signChallenge(new ethers.Wallet(priv), rsKey);
        return R(200, { proof: pc.proof, publicSignals: pc.publicSignals, sig, pk_i: s.pk_i, r_s: rsKey, root: pc.revRoot, regRoot: pc.regRoot, cacheHit: true, timings });
      }
      const t = now();
      let synced;
      try { synced = await chain.syncAll(); }
      catch (e) { return R(503, { reason: 'chain_unavailable', detail: e.message }); }
      timings.syncMs = now() - t;
      lastSync = syncSnapshot(synced);
      await pruneSessions(synced.head);
      if (!(await getSessions())[rsKey]) return R(410, { reason: 'session_expired', timings });   // π 캐시는 바로 위 pruneSessions 가 레코드와 함께 지웠다
      try {
        let out = await proveSession(rsKey, synced, timings, null, src);
        // 시연(가짜 서명): login 과 같다 — 다음 1회만 임의 키로 서명한다.
        const fakeSig = await takeOverride('fake_sig');
        if (fakeSig) out = { ...out, sig: await signChallenge(ethers.Wallet.createRandom(), rsKey), demo: 'override:fake_sig' };
        return R(200, { ...out, timings });
      } catch (e) {
        const mapped = await sessionProofFailure(e, rsKey, timings);
        if (mapped) return mapped;
        if (e.reason === 'no_session') return R(404, { reason: 'no_session', timings });
        throw e;
      }
    },
    /** 에이전트 POST /wallet/request 의 등가 — 세션 안 후속 요청에 세션키로 서명한다(메시지 = `${r_s}:${body}`). */
    async request({ r_s, body, arid = null, origin = null } = {}) {
      if (!isDec(r_s) || typeof body !== 'string') return R(400, { error: 'r_s, body(string) 필요' });
      const rsKey = BigInt(r_s).toString();
      const s = (await getSessions())[rsKey];
      if (!s || !sessionMatches(s, origin, arid)) return R(404, { reason: 'no_session' });
      if (!(await vault.key())) return LOCKED();
      const priv = await sessionKeyOf(rsKey);
      if (!priv) return R(404, { reason: 'no_session' });
      const sig = await signSessionRequest(new ethers.Wallet(priv), BigInt(r_s), body);
      return R(200, { sig, pk_i: s.pk_i });
    },
    /** 에이전트 buildExecute + POST /wallet/tx/prepare 의 등가: 검증 → 동기화 → π(캐시) → 지갑 주소·nonce → 세션키 서명 → execute calldata.
     *  보내는 것은 RP 의 릴레이(계획 R6)다 — 에이전트의 /wallet/tx(provider.getSigner 경로)는 없다. */
    async prepareTx(body) {
      const { r_s, to, value = '0', data = '0x', disclose, set = null } = body ?? {};
      if (!isDec(r_s) || !isAddr(to) || !isDec(value) || typeof data !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(data)) {
        return R(400, { error: 'r_s, to(주소), value(wei 10진, 선택), data(hex, 선택) 필요' });
      }
      const rsKey = BigInt(r_s).toString();
      const s = (await getSessions())[rsKey];
      if (!s) return R(404, { reason: 'no_session' });
      if (!s.factoryAddress) return R(409, { reason: 'no_factory', detail: '서비스가 로그인 때 factoryAddress 를 주지 않았다' });
      if (chainMissing()) return R(503, { reason: 'chain_unavailable', detail: chainMissing() });
      const pubReg = await getReg();
      if (!pubReg) return R(409, { reason: 'not_registered' });
      // 2026-09-22 §4.2 선택 공개: disclose 를 회로 입력으로. 형식·범위 오류·불만족은 체인·증명 작업 전에 걸러낸다(attrs 는 공개 부분).
      let disclosure;
      try {
        // 스키마는 술어가 있을 때만 필요하다 — 술어 없는 tx 는 스키마 상태(schema_invalid)와 무관하게 간다(최종 리뷰 I4).
        if (disclose || set) {
          try { assertPredicateTypes((await schemaFor()).schema, disclose, set); }
          catch (e) {
            if (e.reason === 'schema_invalid') return R(503, { reason: 'schema_invalid', detail: e.message });
            if (e.reason === 'predicate_type') return R(400, { reason: 'predicate_type', detail: e.message });
            throw e;
          }
        }
        const attrs = (pubReg.attrs ?? []).map(BigInt);
        disclosure = { ...normalizeDisclosure(disclose, attrs), ...(await normalizeSet(set, attrs)) };   // V7: 범위 + 집합
      } catch (e) { if (e.reason) return R(400, { reason: e.reason, detail: e.message }); throw e; }
      // 세션키·비밀이 필요하다 — 동기화(전체 재생) 전에 잠김을 본다.
      const src = await source();
      if (src === null) return R(409, { reason: 'not_registered' });
      if (src === 'locked') return LOCKED();
      const timings = { syncMs: 0, issueMs: 0, proveMs: 0, txMs: 0 };
      const t = now();
      let synced;
      try { synced = await chain.syncAll(); }
      catch (e) { return R(503, { reason: 'chain_unavailable', detail: e.message }); }
      timings.syncMs = now() - t;
      lastSync = syncSnapshot(synced);
      await pruneSessions(synced.head);
      if (!(await getSessions())[rsKey]) return R(409, { reason: 'session_expired', timings });   // π 캐시는 바로 위 pruneSessions 가 레코드와 함께 지웠다
      let proved;
      try { proved = await proveSession(rsKey, synced, timings, disclosure, src); }   // root·disclosure 가 같으면 캐시 π, 아니면 재증명
      catch (e) {
        const mapped = await sessionProofFailure(e, rsKey, timings);
        if (mapped) return mapped;
        if (e.reason === 'no_session') return R(404, { reason: 'no_session', timings });
        throw e;
      }
      const walletAddr = await chain.factory(s.factoryAddress).computeAddress(BigInt(s.PPID));
      // 아직 배포 전이면 nonce 는 0(uint256 기본값) — 릴레이가 배포 트랜잭션을 먼저 보낸 뒤 execute 가 이 nonce 로 들어간다
      const deployNeeded = (await provider.getCode(walletAddr)) === '0x';
      const nonce = deployNeeded ? 0n : await walletAt(walletAddr, provider).nonce();
      const payload = { to: ethers.getAddress(to), value: BigInt(value), data, nonce };
      // 시연(가짜 서명, 사용자 요청 2026-10-14): 세션키 대신 임의 키로 서명한다 — 컨트랙트의 _recover 가 복원한 주소가 pub[2](pk_i)와 달라
      // BadSignature 로 거절한다. proveSession 의 signChallenge 가 아니라 여기서 따로 take 하는 이유는 그쪽 sig(세션 챌린지 서명)는 이 경로에서
      // 쓰지 않기 때문이다 — 거기서 소비되면 실제로 보내는 이 서명은 멀쩡한 채로 나간다.
      const fakeSig = await takeOverride('fake_sig');
      const priv = fakeSig ? null : await sessionKeyOf(rsKey);
      if (!fakeSig && !priv) return R(404, { reason: 'no_session', timings });
      const signer = fakeSig ? ethers.Wallet.createRandom() : new ethers.Wallet(priv);
      // 다이제스트의 성명 쪽 다섯 필드(max_height·allowAgent·태그)는 이번에 붙일 π 의 공개 입력에서 그대로 가져온다(2026-09-25 리뷰 A-2).
      const sig = signPayload(signer, { chainId: await chain.chainId(), wallet: walletAddr, ...payload, discMask: disclosure.mask, discLo: disclosure.lo, discHi: disclosure.hi, setSel: disclosure.sel, setRoot: disclosure.root, ...statementDigestFields(proved.publicSignals) });
      const { a, b, c, pub } = await proofToCalldata(proved.proof, proved.publicSignals);
      // demo: fake_proof 는 proveSession 이 이미 proved.demo 로 알려줬고, fake_sig 는 여기서 막 소비했다 — 둘은 같은 요청에서 동시에 일어날 수 없다.
      const demo = proved.demo ?? (fakeSig ? 'override:fake_sig' : undefined);
      return R(200, {
        walletAddr, factoryAddress: s.factoryAddress, deployNeeded,
        deployCalldata: deployNeeded ? factoryInterface.encodeFunctionData('deploy', [BigInt(s.PPID)]) : null,
        calldata: walletInterface.encodeFunctionData('execute', [payload, sig, a, b, c, pub]),
        nonce: nonce.toString(), disclosure: hasPredicate(disclosure) ? discStrings(disclosure) : null,
        cacheHit: proved.cacheHit, root: proved.root, regRoot: proved.regRoot, timings, ...(demo ? { demo } : {}),
      });
    },
    /** 에이전트 POST /wallet/tx/record 의 등가 — 릴레이가 보낸 execute 의 영수증을 provider 로 읽어 파싱한다. 아직 없으면 202 { pending:true }
     *  (기다리지 않는다 — 화면이 다시 부른다). 요청값 disclosure 는 calldata 의 pub 에서 되돌린다. 처음 보는 txHash 면 txs 에 한 번 남긴다
     *  (health 의 txs·disclosedTxs 가 다시 읽기를 넘긴다). */
    async recordTx({ r_s, txHash } = {}) {
      if (!isDec(r_s) || typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return R(400, { error: 'r_s, txHash(32바이트 hex) 필요' });
      const rsKey = BigInt(r_s).toString();
      const s = (await getSessions())[rsKey];
      if (!s) return R(404, { reason: 'no_session' });
      if (!s.factoryAddress) return R(409, { reason: 'no_factory' });
      const walletAddr = await chain.factory(s.factoryAddress).computeAddress(BigInt(s.PPID));
      const [receipt, tx] = await Promise.all([provider.getTransactionReceipt(txHash), provider.getTransaction(txHash)]);
      if (!receipt) return R(202, { pending: true, txHash, wallet: walletAddr });
      // 이 세션의 지갑으로 간 트랜잭션만 받는다 — 배포 tx 나 남의 트랜잭션을 실행 결과로 오인하지 않는다(리뷰 Minor)
      const txTo = receipt.to ?? tx?.to ?? null;
      if (!txTo || txTo.toLowerCase() !== walletAddr.toLowerCase()) return R(409, { reason: 'not_our_tx', txHash, wallet: walletAddr });
      let disclosure = null;
      const dec = tx ? decodeExecuteCalldata(tx.data) : null;
      if (dec) { const pub = dec.pub.map(BigInt); disclosure = { mask: pub[PUB_INDEX.DISC_MASK], lo: pub.slice(PUB_INDEX.DISC_LO, PUB_INDEX.DISC_HI), hi: pub.slice(PUB_INDEX.DISC_HI, PUB_INDEX.SET_SEL), sel: pub[PUB_INDEX.SET_SEL], root: pub[PUB_INDEX.SET_ROOT] }; }
      const result = receiptResult(receipt, walletAddr, disclosure);
      const txs = await getTxs();
      if (!txs.some((x) => x.txHash === txHash)) {
        const disclosed = Boolean(disclosure) && (disclosure.mask !== 0n || (disclosure.sel ?? 0n) !== 0n);
        txs.push({ txHash, r_s: rsKey, at: new Date(now()).toISOString(), ok: result.ok, disclosed, wallet: walletAddr, nonce: result.nonce });
        await kv.set('txs', txs);
      }
      return R(200, result);
    },
    /** 에이전트 POST /wallet/session/revoke 의 등가(V8 세션 폐기, 설계 2026-09-24 §4): 이 지갑의 세션 하나를 AA 에 폐기 요청한다. 서명은
     *  금고의 sk_u. AA 가 받아들이면 세션·세션키·π 캐시를 지운다. */
    async revokeSession({ r_s } = {}) {
      if (!isDec(r_s)) return R(400, { error: 'r_s 필요' });
      const rsKey = BigInt(r_s).toString();
      const s = (await getSessions())[rsKey];
      if (!s) return R(404, { reason: 'no_session' });
      const reg = await getReg();
      if (!reg) return R(409, { reason: 'not_registered' });
      if (!(await vault.key())) return LOCKED();
      const sk_u = (await vault.readSecrets()).sk_u;
      if (!sk_u) return R(500, { reason: 'internal', detail: '금고에 sk_u 가 없다' });
      const nonce = randomScalar();   // 신선도는 IdP 가 보지 않는다(재생 = 같은 세션 재폐기, 멱등)
      const sig_u = await signRevokeSession(sk_u, BigInt(reg.uid), BigInt(s.credential.Cf_s), nonce);
      // 502 cia_unavailable 은 **IdP 호출 실패만** 가리킨다(최종 리뷰 F3). 서명·BigInt 같은 지역 오류는 500 internal 로 간다.
      let r;
      try { r = await idp.post('/cia/revoke', { uid: reg.uid, scope: 'session', Cf_s: s.credential.Cf_s, sig_u, nonce: nonce.toString() }); }
      catch (e) { return R(502, { reason: 'cia_unavailable', detail: e.message }); }
      if (r.status !== 200) return R(r.status, r.body ?? {});
      // AA 가 받아들인 순간부터 이 지갑은 그 세션을 더 쓰지 않는다 — 게시 전이라도(게시 뒤에는 어차피 π 가 안 만들어진다).
      await deleteSession(rsKey);
      return R(200, { revoked: true, inserted: r.body.inserted, pending: r.body.pending });
    },
    /** 에이전트 POST /wallet/self_revoke 의 등가 — IdP /cia/account/self_revoke 를 직접 부른다(cia.js CORS, Task 6). 비밀번호는 넘길 뿐
     *  어디에도 남기지 않는다. 이 지갑이 들고 있는 계정만 — 임의 uid·pwd 를 IdP 에 던져 보는 통로가 되지 않게. */
    async selfRevoke({ uid, pwd } = {}) {
      if (!isDec(uid) || typeof pwd !== 'string') return R(400, { error: 'uid(10진 문자열), pwd 필요' });
      const reg = await getReg();
      if (!reg) return R(409, { reason: 'not_registered' });
      if (uid !== reg.uid) return R(403, { reason: 'uid_mismatch' });
      try { const r = await idp.post('/cia/account/self_revoke', { uid, pwd }); return R(r.status, r.body ?? {}); }
      catch (e) { return R(502, { reason: 'cia_unavailable', detail: e.message }); }
    },
    /** Google(OIDC) 계정의 자기 폐기(스펙 2026-10-16 §3.3) — 폐기용 nonce("revoke:…")로 받은 id_token 을 IdP 에 넘긴다. 토큰이 가리키는 계정·
     *  provider·nonce 목적은 IdP 가 검증한다(등록 토큰은 400 oidc_nonce_mismatch). 토큰은 넘길 뿐 어디에도 남기지 않는다. */
    async selfRevokeWithIdToken({ idToken } = {}) {
      if (typeof idToken !== 'string' || !idToken) return R(400, { error: 'idToken(문자열) 필요' });
      const reg = await getReg();
      if (!reg) return R(409, { reason: 'not_registered' });
      try { const r = await idp.post('/cia/account/self_revoke', { id_token: idToken }); return R(r.status, r.body ?? {}); }
      catch (e) { return R(502, { reason: 'cia_unavailable', detail: e.message }); }
    },
    /** 에이전트 POST /wallet/demo/override 의 등가(설계 §8.3, 2026-10-14 확장): 다음 발급/증명/서명을 한 번만 덮어쓴다(kv `demo`).
     *  issue·prove: s_u·uid 를 바꿔친다. fake_proof·fake_sig: 발급·증명은 정상으로 끝내고 **보내는 복사본**만 바꿔친다. */
    async demoOverride({ scope = null, s_u = null, uid: uidIn = null, clear = false } = {}) {
      if (clear) { await kv.del('demo'); return R(200, { ok: true, override: null }); }
      if (!['issue', 'prove', 'fake_proof', 'fake_sig'].includes(scope)) return R(400, { error: "scope 는 'issue'·'prove'·'fake_proof'·'fake_sig' 중 하나" });
      if (scope === 'fake_proof' || scope === 'fake_sig') { await kv.set('demo', { scope }); return R(200, { ok: true, override: { scope, fields: [] } }); }
      if ((s_u !== null && (!isDec(s_u) || BigInt(s_u) >= SCALAR_MAX)) || (uidIn !== null && (!isDec(uidIn) || BigInt(uidIn) >= SCALAR_MAX))) return R(400, { error: 's_u·uid 는 10진, 2^250 미만' });
      if (s_u === null && uidIn === null) return R(400, { error: 's_u 또는 uid 가 필요하다' });
      const ov = { scope, ...(s_u !== null ? { s_u } : {}), ...(uidIn !== null ? { uid: uidIn } : {}) };
      await kv.set('demo', ov);
      return R(200, { ok: true, override: { scope, fields: Object.keys(ov).filter((k) => k !== 'scope') } });
    },
    /** 이 브라우저의 등록·비밀·세션을 모두 지운다(되돌릴 수 없다 — IdP 쪽 계정은 그대로). */
    async wipe() { await kv.clear(); vault.reset(); lastSync = null; lastRegistry = null; pendingReg = null; return R(200, { ok: true }); },
  };
  /** execute 영수증 → 응답 공통부(에이전트 receiptResult 의 등가). disclosure = 요청값, onchainDisclosure = Disclosure 이벤트에서 읽은 값. */
  function receiptResult(receipt, walletAddr, disclosure) {
    const parsed = parseExecuteReceipt(receipt, walletAddr);
    return {
      txHash: receipt.hash, wallet: walletAddr, status: receipt.status, ok: parsed.executed?.success ?? null, gasUsed: receipt.gasUsed.toString(),
      nonce: parsed.executed ? parsed.executed.nonceUsed.toString() : null,
      executed: parsed.executed ? { nonceUsed: parsed.executed.nonceUsed.toString(), to: parsed.executed.to, value: parsed.executed.value.toString(), success: parsed.executed.success } : null,
      disclosure: hasPredicate(disclosure) ? discStrings(disclosure) : null,
      onchainDisclosure: discStrings(parsed.disclosure),
    };
  }
  // 모든 동작은 던지지 않는다(에이전트의 라우트 catch·전역 오류 핸들러 자리): 금고가 도중에 잠기면(만료) 423, 그 밖은 500 internal.
  const guard = (name, fn) => async (...args) => {
    try { return await fn(...args); }
    catch (e) {
      if (e?.reason === 'locked') return LOCKED();
      // 워커·자산 로더가 태그한 사유는 보존한다(페이지가 "증명 키를 받을 수 없습니다" 로 안내).
      if (e?.reason === 'zk_assets_unavailable') return R(503, { reason: 'zk_assets_unavailable', detail: e.message });
      log(`[user-core] ${name} 처리되지 않은 오류: ${e?.stack ?? e}`);
      return R(500, { reason: 'internal', detail: e?.message ?? String(e) });
    }
  };
  const core = { vault, chain, idp };
  for (const [name, fn] of Object.entries(ops)) core[name] = guard(name, fn);
  /** Google(OIDC) 등록 1단계(스펙 2026-10-16 §3.1): 등록 재료(s_u·sk_u·pk_u)를 먼저 만들고 토큰을 그 공개키에 묶을 nonce = regNonce(pk_u) 를
   *  낸다 — uid 는 토큰의 sub 로 정해지므로 auid 는 completeRegistration 에서 만든다. 재료는 이 페이지의 메모리(pendingReg)에만 두고,
   *  부를 때마다 새로 만든다(토큰은 1회용). { status, body } 가 아니라 { nonce, pk_u:{x,y}(10진 문자열), pending:true } 를 돌려준다. */
  core.prepareRegistration = async () => {
    const s_u = randomScalar();
    const sk_u = randomBytes(32).toString('hex');
    const pk = await eddsaPubOf(sk_u);
    const pk_u = { x: pk.x.toString(), y: pk.y.toString() };
    const nonce = regNonce(pk_u);
    pendingReg = { s_u, sk_u, pk_u, nonce };
    return { nonce, pk_u, pending: true };
  };
  /** 존재 신호 6개(정적 서버 POST /wallet/presence 의 본문). 세션 수·rpCount 는 저장 세션에서, txs·disclosedTxs 는 txs 배열에서 센다 —
   *  다시 읽기를 넘긴다. rpCount 는 "지금 몇 RP 에 로그인 상태인가"다(세션이 지워지면 함께 준다). 던지지 않는다. */
  core.health = async () => {
    try {
      const reg = await getReg(); const sessions = await getSessions(); const txs = await getTxs();
      return { registered: Boolean(reg), hasCred: Boolean(reg?.userCred), sessions: Object.keys(sessions).length, rpCount: new Set(Object.values(sessions).map((s) => String(s.arid))).size, txs: txs.length, disclosedTxs: txs.filter((t) => t.disclosed).length };
    } catch (e) {
      log(`[user-core] health 오류: ${e?.stack ?? e}`);
      return { registered: false, hasCred: false, sessions: 0, rpCount: 0, txs: 0, disclosedTxs: 0 };
    }
  };
  return core;
}
