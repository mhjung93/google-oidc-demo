// IdP 상태 파일의 버전과 검사 — cia.js 에서 떼어 낸 순수 함수. 체인·키 없이 테스트한다.
//
// version 12 (2026-10-12, V11 그림 프로토콜): accounts[uid].auid(필수) 가 cm_u 를 대체하고 attrs·profile 이 없어졌다(D4·D15), 등록부 리프는 Poseidon(auid, Cf_u).
//   **v11 이하는 이행하지 않는다** — 옛 계정의 auid 는 IdP 가 알 수 없고(지갑만 s_u 로 계산한다) 리프·PPID 식이 바뀌어 체인도 새로 배포해야 하므로,
//   V5·V9 때와 같은 "로그 재배포 → 상태 파일 새로" 절차(docs/MODE3_DEMO.md 재시연 세트)로 새로 시작한다. v3~v11 의 이행 코드는 git 이력(78b2a1f)에 있다.
// Task 10(B1, 2026-10-22, 스펙 2026-10-22-mode3-idp-pages-design.md §3.1~3.3): 버전은 그대로 12 다 — 계정 비밀번호·1회용 코드는 v12 의
//   확장(새 필드, ??= 로 옛 파일을 채운다)이지 스키마 교체가 아니다. 가입만 하고 등록 전인 계정은 pk_u:null·auid:null·slot:null
//   (등록은 그 자리를 채운다 — pwSalt·pwHash·createdAt 은 그대로 보존).
// 모양: accounts[uid] = { pwSalt(16B hex)|null, pwHash(scrypt(pwd,salt) hex)|null, pwAlgo('scrypt')|null, createdAt, pk_u:{x,y}|null, auid(10진)|null, slot|null,
//         tampered, disabled, creds:[{ Cf_u, C_u_pt, issuedAt, revoked }], sessions:[{ Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt }], receipt, slotRetired }
//       rps / openings / revoked / pending / epoch / registry { depth, next, leaves, pendingSlots } / lastPublication / signedEpochMax / attrSchemaHash /
//       nextUid(다음 가입 uid, 시작 100001) / codes { [code]: { uid, purpose, auid, expiresAt } } (1회용 코드, 소비 시 삭제)
export const CIA_STATE_VERSION = 12;

export function defaultCiaState() {
  return { version: CIA_STATE_VERSION, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 0, leaves: {}, pendingSlots: [] }, lastPublication: null, signedEpochMax: 0, attrSchemaHash: null, nextUid: 100001, codes: {} };
}

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isPt = (p) => p !== null && typeof p === 'object' && isDec(p.x) && isDec(p.y);

/** 제자리 검사. notes 는 기동 로그용(지금은 늘 빈 배열 — 이행이 없다). 버전이 다르면 throw — cia.js 가 사유를 찍고 기동을 거부한다. */
export function migrateCiaState(state) {
  if (state?.version !== CIA_STATE_VERSION) {
    throw new Error(`unsupported IdP state version ${state?.version} (expected ${CIA_STATE_VERSION}) — V11(2026-10-12)은 옛 상태를 이행하지 않는다: 계정의 auid 는 지갑만 계산할 수 있고 등록부 리프·PPID 식이 바뀌어 체인도 새로 배포해야 한다. 재시연 세트(로그·거울 재배포 → 상태 파일 새로)로 시작할 것`);
  }
  state.accounts ??= {}; state.rps ??= {}; state.openings ??= []; state.revoked ??= []; state.pending ??= []; state.epoch ??= 0;
  state.registry ??= { depth: 20, next: 0, leaves: {}, pendingSlots: [] };
  // 손으로 적은(또는 깨진) 파일이 registry 는 있는데 하위 필드가 빠진 경우를 방어한다(2026-10-01 리뷰 Minor).
  state.registry.depth ??= 20; state.registry.next ??= 0; state.registry.leaves ??= {}; state.registry.pendingSlots ??= [];
  state.lastPublication ??= null; state.signedEpochMax ??= 0; state.attrSchemaHash ??= null;
  // Task 10(B1, 2026-10-22): 가입 전용 계정 번호·1회용 코드 저장소. 옛(이 필드 이전) 파일에 기본값을 채운다 — 버전은 그대로 12.
  state.nextUid ??= 100001; state.codes ??= {};
  for (const [uid, a] of Object.entries(state.accounts)) {
    if (a.pk_u === null) {
      // 가입(§3.1)만 하고 등록 전인 계정(Task 10) — auid·slot 도 아직 없다(null). 둘 중 하나만 채워져 있으면 손상된 상태다.
      if (a.auid !== null) throw new Error(`IdP state: account ${uid} 는 등록 전(pk_u:null)인데 auid 가 null 이 아니다`);
      if (a.slot !== null) throw new Error(`IdP state: account ${uid} 는 등록 전(pk_u:null)인데 slot 이 null 이 아니다`);
    } else {
      if (!isDec(a.auid)) throw new Error(`IdP state: account ${uid} has no auid — v12 계정은 auid(10진 문자열)가 필수다`);
      // 리뷰 S5(2026-10-13): 손으로 고친 파일의 slot·pk_u 를 기동 때 거른다 — 그대로 뜨면 /cia/issue 중 setSlot 이 throw 해 반쯤 바뀐 상태가
      // persist 되고(slot), 서명 검증이 엉뚱한 키로 돈다(pk_u). 둘 다 /cia/register 가 늘 채우는 값이다.
      if (!Number.isInteger(a.slot) || a.slot < 0) throw new Error(`IdP state: account ${uid} has no valid slot — 음이 아닌 정수여야 한다`);
      if (!isPt(a.pk_u)) throw new Error(`IdP state: account ${uid} has no valid pk_u — {x, y} 10진 문자열이어야 한다`);
    }
    a.creds ??= []; a.sessions ??= []; a.tampered ??= false; a.receipt ??= null; a.slotRetired ??= false;
    a.provider ??= 'demo';   // OIDC 래퍼(2026-10-16): provider 가 없던 옛 계정은 데모 계정이다
    // Task 10(B1): 비밀번호가 없는 옛 계정(이 필드 이전)은 비밀번호 로그인만 못 하는 레거시 계정이다 — 등록·발급 흐름은 그대로.
    // pwAlgo(보안 리뷰 2026-10-23, scrypt): pwHash 가 있는데 pwAlgo 가 없는 레코드는 scrypt 로 본다(이 필드 이전엔 scrypt 뿐이었다).
    a.pwSalt ??= null; a.pwHash ??= null; a.createdAt ??= null;
    a.pwAlgo ??= (a.pwHash ? 'scrypt' : null);
    if ('attrs' in a || 'profile' in a || 'cm_u' in a) throw new Error(`IdP state: account ${uid} has V10 fields (attrs/profile/cm_u) — v12 계정에는 없어야 한다(D15·D4)`);
  }
  return { state, notes: [] };
}
