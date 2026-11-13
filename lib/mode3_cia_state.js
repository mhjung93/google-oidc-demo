// IdP 상태 파일의 버전과 검사 — cia.js 에서 떼어 낸 순수 함수. 체인·키 없이 테스트한다.
//
// version 12 (2026-10-12, V11 그림 프로토콜): accounts[uid].auid(필수) 가 cm_u 를 대체하고 attrs·profile 이 없어졌다(D4·D15), 등록부 리프는 Poseidon(auid, Cf_u).
//   **v11 이하는 이행하지 않는다** — 옛 계정의 auid 는 IdP 가 알 수 없고(지갑만 s_u 로 계산한다) 리프·PPID 식이 바뀌어 체인도 새로 배포해야 하므로,
//   V5·V9 때와 같은 "로그 재배포 → 상태 파일 새로" 절차(docs/MODE3_DEMO.md 재시연 세트)로 새로 시작한다. v3~v11 의 이행 코드는 git 이력(78b2a1f)에 있다.
// Task 10(B1, 2026-10-22, 스펙 2026-10-22-mode3-idp-pages-design.md §3.1~3.3): 버전은 그대로 12 다 — 계정 비밀번호·1회용 코드는 v12 의
//   확장(새 필드, ??= 로 옛 파일을 채운다)이지 스키마 교체가 아니다. 가입만 하고 등록 전인 계정은 pk_u:null·auid:null·slot:null
//   (등록은 그 자리를 채운다 — pwSalt·pwHash·createdAt 은 그대로 보존).
// Task 11(B2, 2026-10-22, 같은 스펙 §3.3): RP 운영자 계정(operators)·RP 슬롯(rpSlots)·rps[arid].operator 도 같은 식의 확장이다
//   (버전은 그대로 12). operators[id] 는 accounts 의 비밀번호 필드와 같은 모양(pwSalt·pwHash·pwAlgo·createdAt). rpSlots[slotId] 는
//   rp_key 를 "같은 헬퍼로" 해시해 둔다(pwSalt·pwHash·pwAlgo — 평문은 생성 응답에만 나가고 상태에는 없다). 옛(이 필드 이전) rps
//   엔트리는 operator:null 인 레거시 RP 로 읽힌다(컨트롤러 판정, task-11-addendum.md).
// version 13 (2026-11-13, 스펙 2026-11-12 no-pk-u §5): 등록 키 pk_u 가 없어졌다. "등록됨" 의 표지는 auid 다 — 등록 전 = auid:null·slot:null,
//   등록됨 = auid(10진)·slot(정수). v12 는 받아서 계정마다 pk_u 를 지우고 13 으로 올린다(auid 는 그대로라 재등록이 없다). 13 에 pk_u 가 남아 있어도
//   (손으로 고친 파일) 같은 식으로 지운다. **옛 코드는 13 파일을 거부한다** — 되돌리려면 반영 전에 떠 둔 상태 파일 사본이 필요하다.
//   연결 해제(/cia/user/unlink_wallet)된 계정은 auid:null 인 채 옛 slot 번호와 slotRetired:true 를 갖는다 — 그 모양은 받는다(전에는 기동을 거부했다).
// version 14 (2026-11-13, 스펙 2026-11-13 random-salt R10·R11·R14): auid 의 뜻이 바뀌었다 — auid = Poseidon(T_AUID2, salt)(uid 없음, 스냅의 가명)이고 PPID 에서도 uid 가 빠졌다.
//   옛 상태(13 이하)의 auid·등록부 리프는 새 식의 값이 아니라 이행할 수 없다 — **14 만 받는다**(12 → 13 이행도 없앴다). 옛 파일은 기동을 거부하고 데모 리셋을 안내한다.
//   같은 IdP 에서 한 스냅(같은 auid)의 **활성** 계정은 하나다(cia.js registerAccount 가 auid_taken 으로 거절). 폐기된(disabled) 계정은 스냅을 쥐지 않는다 —
//   그래서 같은 auid 가 폐기된 계정과 활성 계정에 함께 있을 수 있다(2026-11-13 사용자 결정).
// 모양: accounts[uid] = { pwSalt(16B hex)|null, pwHash(scrypt(pwd,salt) hex)|null, pwAlgo('scrypt')|null, createdAt, auid(10진)|null, slot|null,
//         tampered, disabled, creds:[{ Cf_u, C_u_pt, issuedAt, revoked }], sessions:[{ Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt, bound, pk_i? }], receipt, slotRetired,
//         (2026-11-09 의 linked 는 2026-11-10 에 없앴다 — 열 때 지운다),
//         lastAuidS: { value(10진), at } | null (2026-11-12 사용자 결정 — D1 수정: 가장 최신 auid_s 하나만 덮어써 둔다. 기록은 남기지 않는다) }
//       rps[arid] += { operator(운영자 id)|null } / operators[id] = { pwSalt, pwHash, pwAlgo, createdAt } /
//       rpSlots[slotId] = { opId, name, origin(서비스 주소, 2026-11-06 — 옛 슬롯엔 없음), pwSalt, pwHash, pwAlgo(rp_key 해시), keyTag(SHA-256(rp_key) hex — 조회 인덱스, 2026-10-26 리뷰 C2; 옛 슬롯엔 없음), status('created'|'pending'), createdAt, arid|null } /
//       openings / revoked / pending / epoch / registry { depth, next, leaves, pendingSlots } / pendingBounds [{ pk_i(10진), bound(10진), epoch(마지막으로 실린 게시 epoch, 10진)|null }] (2026-10-25 root 창 §4 — 거울 공개 세션 counter 대기열) / lastPublication / signedEpochMax / attrSchemaHash /
//       nextUid(다음 가입 uid, 시작 100001) / codes { [code]: { uid, purpose, auid, expiresAt } } (1회용 코드, 소비 시 삭제)
//       loginIds { [소문자 아이디]: uid } (2026-11-03 아이디 가입 — accounts[uid].loginId 의 조회 색인; 시드·Google 계정은 loginId:null 일 수 있다)
import { createHash } from 'node:crypto';

export const CIA_STATE_VERSION = 14;
const ACCEPTED_VERSIONS = new Set([14]);

export function defaultCiaState() {
  return { version: CIA_STATE_VERSION, accounts: {}, rps: {}, operators: {}, rpSlots: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 0, leaves: {}, pendingSlots: [] }, pendingBounds: [], lastPublication: null, signedEpochMax: 0, attrSchemaHash: null, nextUid: 100001, codes: {}, loginIds: {} };
}

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);

/** 제자리 검사·이행. notes 는 기동 로그용(loginId 중복을 지운 경우 등에 찬다). 버전이 14 가 아니면 throw — cia.js 가 사유를 찍고 기동을 거부한다. */
export function migrateCiaState(state) {
  if (!ACCEPTED_VERSIONS.has(state?.version)) {
    throw new Error(`unsupported IdP state version ${state?.version} (expected ${CIA_STATE_VERSION}) — 2026-11-13(스펙 random-salt R14): auid·PPID 식이 바뀌어(uid 를 뺐다) 옛 상태를 이행하지 않는다. 등록부 리프·지갑 주소가 모두 달라져 체인도 새로 배포해야 한다. 데모 리셋(상태 파일을 옮겨 두고 새로 시작 — 지우지는 않는다)으로 시작할 것`);
  }
  const notes = [];
  state.accounts ??= {}; state.rps ??= {}; state.openings ??= []; state.revoked ??= []; state.pending ??= []; state.epoch ??= 0;
  state.registry ??= { depth: 20, next: 0, leaves: {}, pendingSlots: [] };
  // 손으로 적은(또는 깨진) 파일이 registry 는 있는데 하위 필드가 빠진 경우를 방어한다(2026-10-01 리뷰 Minor).
  state.registry.depth ??= 20; state.registry.next ??= 0; state.registry.leaves ??= {}; state.registry.pendingSlots ??= [];
  state.pendingBounds ??= [];
  state.lastPublication ??= null; state.signedEpochMax ??= 0; state.attrSchemaHash ??= null;
  // Task 10(B1, 2026-10-22): 가입 전용 계정 번호·1회용 코드 저장소. 옛(이 필드 이전) 파일에 기본값을 채운다 — 버전은 그대로 12.
  state.nextUid ??= 100001; state.codes ??= {};
  // 2026-11-03 아이디 가입: loginIds 색인. 옛 파일에는 없으므로 빈 값으로 두고 아래 계정 루프에서 loginId 가 있는 계정을 다시 채운다 — 버전은 그대로 12.
  state.loginIds = {};   // 리뷰(2026-11-03) M-4: 색인은 accounts 에서 늘 다시 만든다 — 손으로 적은 파일의 잘못된 항목이 남지 않게
  // Task 11(B2, 2026-10-22): RP 운영자 계정·RP 슬롯 저장소. 옛(이 필드 이전) 파일에 빈 값을 채운다 — 버전은 그대로 12.
  state.operators ??= {}; state.rpSlots ??= {};
  // 옛(Task 11 이전) rps 엔트리에는 operator 가 없다 — 운영자 없는 레거시 RP 로 읽는다(컨트롤러 판정).
  for (const e of Object.values(state.rps)) e.operator ??= null;
  for (const [uid, a] of Object.entries(state.accounts)) {
    delete a.pk_u;   // v13 부터 등록 키는 없다 — 손으로 고친 파일에 남은 값은 지운다
    if (a.auid === null) {
      // 가입(§3.1)만 하고 등록 전이거나, 연결 해제로 등록을 푼 계정. 연결 해제는 옛 slot 번호를 남기고 slotRetired 를 건다(재등록 때 새 번호를 받는다).
      const unlinked = a.slotRetired === true && Number.isInteger(a.slot) && a.slot >= 0;
      if (a.slot !== null && !unlinked) throw new Error(`IdP state: account ${uid} 는 등록 전(auid:null)인데 slot 이 null 이 아니다`);
    } else {
      if (!isDec(a.auid)) throw new Error(`IdP state: account ${uid} has no auid — 등록된 계정은 auid(10진 문자열)가 필수다`);
      // 리뷰 S5(2026-10-13): 손으로 고친 파일의 slot 을 기동 때 거른다 — 그대로 뜨면 /cia/issue 중 setSlot 이 throw 해 반쯤 바뀐 상태가 persist 된다.
      if (!Number.isInteger(a.slot) || a.slot < 0) throw new Error(`IdP state: account ${uid} has no valid slot — 음이 아닌 정수여야 한다`);
    }
    a.creds ??= []; a.sessions ??= []; a.tampered ??= false; a.receipt ??= null; a.slotRetired ??= false;
    // 2026-11-12(사용자 결정 — D1 수정): 계정마다 가장 최신 auid_s 하나({ value, at })만 둔다. 옛 파일에는 없다 — null. 버전은 그대로 12(확장).
    a.lastAuidS ??= null;
    if (a.lastAuidS !== null && !(typeof a.lastAuidS === 'object' && !Array.isArray(a.lastAuidS) && isDec(a.lastAuidS.value) && typeof a.lastAuidS.at === 'string')) {
      throw new Error(`IdP state: account ${uid} 의 lastAuidS 는 { value(10진 문자열), at } 또는 null 이어야 한다`);
    }
    a.provider ??= 'demo';   // OIDC 래퍼(2026-10-16): provider 가 없던 옛 계정은 데모 계정이다
    // 2026-11-10: 11-09 zkID 쪽 연결(linked·옛 linkedOidc)은 RP 로 옮겨 없앴다 — 남아 있으면 지운다(IdP 가 더 쓰지 않는다).
    if ('linked' in a || 'linkedOidc' in a) { delete a.linked; delete a.linkedOidc; notes.push(`계정 ${uid}: 옛 linked·linkedOidc 를 지웠다(2026-11-10 RP 직접 연결로 대체)`); }
    a.loginId ??= null;      // 아이디 가입(2026-11-03) 이전 계정·시드·Google 계정은 아이디가 없다 — uid 로만 로그인한다
    if (typeof a.loginId === 'string' && a.loginId) {
      const k = a.loginId.toLowerCase();
      if (state.loginIds[k] && state.loginIds[k] !== uid) { notes.push(`loginId '${a.loginId}' 중복 — uid ${state.loginIds[k]} 가 쓴다; uid ${uid} 는 아이디를 비우고 uid 로만 로그인`); a.loginId = null; }
      else state.loginIds[k] = uid;
    }
    // Task 10(B1): 비밀번호가 없는 옛 계정(이 필드 이전)은 비밀번호 로그인만 못 하는 레거시 계정이다 — 등록·발급 흐름은 그대로.
    // pwAlgo(보안 리뷰 2026-10-23, scrypt): pwHash 가 있는데 pwAlgo 가 없는 레코드는 scrypt 로 본다(이 필드 이전엔 scrypt 뿐이었다).
    a.pwSalt ??= null; a.pwHash ??= null; a.createdAt ??= null;
    a.pwAlgo ??= (a.pwHash ? 'scrypt' : null);
    if ('attrs' in a || 'cm_u' in a) throw new Error(`IdP state: account ${uid} has V10 fields (attrs/cm_u) — v12 계정에는 없어야 한다(D15·D4)`);
    // profile(2026-11-09 Phase 1): OIDC name 한 칸 { name, updatedAt } 만 허용한다 — V10 의 속성 profile(슬롯 이름 → 값)은 여전히 거부(D15).
    if ('profile' in a) {
      const p = a.profile;
      const ok = p !== null && typeof p === 'object' && !Array.isArray(p) && typeof p.name === 'string' && Object.keys(p).every((k) => k === 'name' || k === 'updatedAt');
      if (!ok) throw new Error(`IdP state: account ${uid} has V10 fields (profile) — v12 계정의 profile 은 { name, updatedAt } 뿐이어야 한다(D15)`);
    }
  }
  return { state, notes };
}

// ---- RP 슬롯 조회(리뷰 C2, 2026-10-26) ----
// 예전엔 register_rp 가 'created' 슬롯마다 scrypt(pwOk) 를 돌았다 — 무인증 요청 1건이 슬롯 수 × scrypt 만큼 이벤트 루프를 멈췄다.
// 이제 슬롯을 만들 때 keyTag = SHA-256(rp_key) 를 같이 적어 두고, 조회는 태그 문자열 비교로 한 슬롯을 찾은 뒤 그 슬롯에만 scrypt 를 한 번 돈다.
// rp_key 는 IdP 가 만드는 32B 난수(256비트)라 사람이 고른 비밀번호가 아니다 — 무차별 대입이 불가능하므로 솔트 없는 빠른 해시를
// 인덱스로 써도 된다(태그가 새어도 원상을 찾을 수 없다). 태그 비교가 timing-safe 가 아니어도 같은 이유로 문제없다.
/** rp_key 의 조회 태그(64자 hex). */
export const rpKeyTag = (rp_key) => createHash('sha256').update(String(rp_key), 'utf8').digest('hex');
/** 'created' 슬롯 중 rp_key 에 맞는 것(없으면 null). verify(slot, rp_key) 는 scrypt 대조(cia.js 의 pwOk) — 태그가 맞은 슬롯에만 한 번 부른다.
 *  태그가 맞는 슬롯이 없으면 keyTag 가 없는 레거시 슬롯(이 필드 이전의 상태 파일)만 훑는다 — 레거시 슬롯은 더 생기지 않으므로 그 수에 묶인다. */
export function findRpSlotByKey(rpSlots, rp_key, verify) {
  const created = Object.values(rpSlots ?? {}).filter((s) => s.status === 'created');
  const tag = rpKeyTag(rp_key);
  const tagged = created.find((s) => s.keyTag === tag);
  if (tagged) return verify(tagged, rp_key) ? tagged : null;
  return created.find((s) => !s.keyTag && verify(s, rp_key)) ?? null;
}
