// CIA 상태 파일의 버전과 이행 — cia.js 에서 떼어 낸 순수 함수(설계 2026-09-18 §4.4). 체인·키 없이 테스트한다.
//
// version 4 (2026-09-16): used_rs 삭제, rps 에 키·상태, openings 추가.
// version 5 (2026-09-18): 발급 기록 형식 { leaf, C, max_height, chainid } — 옛 exptime 기록은 V3 서명 자격증명이라
//   새 회로·컨트랙트·서비스 검증기 어디서도 검증되지 않으므로 폐기 대상이 아니다 → 비운다. 기록 키는 (leaf, chainid) 다 —
//   leaf 는 C 에서만 유도돼 chainid 를 타지 않으므로, 같은 C_pt 를 두 체인으로 발급하면 leaf 가 같은 항목이 두 개(체인별로
//   하나) 있을 수 있다. openings 에 resolved(역조회 성공 여부)·allowAgent·max_height·chainid 를 둔다(옛 항목은 null).
// version 6 (2026-09-21): 자격증명 이중 구조. accounts[uid].creds = [{ Cf_u, C_u_pt, leaf, issuedAt, revoked }] (사용자당 활성 하나).
//   issued(세션 기록) 삭제 — 폐기 리프가 C_u 에서 나오므로 세션 기록이 필요 없다(설계 §4.2·§4.4).
export const CIA_STATE_VERSION = 6;

export function defaultCiaState() {
  return { version: CIA_STATE_VERSION, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 };
}

/** 제자리 이행. 돌려주는 notes 는 기동 로그용 한 줄씩. v2 이하는 옛 서명 형식이라 읽지 않는다(throw). */
export function migrateCiaState(state) {
  const notes = [];
  if (state.version === 3) {
    delete state.used_rs;
    for (const e of Object.values(state.rps ?? {})) {
      e.pk_service ??= null; e.X_svc ??= null; e.x_AA ??= null; e.pk_trace ??= null;
      e.status ??= 'approved'; e.requestedAt ??= e.at ?? new Date().toISOString(); e.decidedAt ??= e.requestedAt;
    }
    state.openings ??= [];
    state.version = 4;
    notes.push('v3→v4: used_rs 버림, 기존 서비스 등록은 approved(조각 없음)');
  }
  if (state.version === 4) {
    const dropped = Object.values(state.issued ?? {}).reduce((n, l) => n + (Array.isArray(l) ? l.length : 0), 0);
    state.issued = {};
    for (const o of state.openings ?? []) {
      o.resolved ??= (o.status === 'approved' ? Boolean(o.uid) : null);
      o.allowAgent ??= null; o.max_height ??= null; o.chainid ??= null;
    }
    state.version = 5;
    notes.push(`v4→v5: 발급 기록 ${dropped}개 버림(V3 서명은 새 회로에서 검증되지 않는다), openings 에 resolved·allowAgent·max_height·chainid`);
  }
  if (state.version === 5) {
    const dropped = Object.values(state.issued ?? {}).reduce((n, l) => n + (Array.isArray(l) ? l.length : 0), 0);
    delete state.issued;
    for (const a of Object.values(state.accounts ?? {})) a.creds ??= [];
    state.version = 6;
    notes.push(`v5→v6: 세션 발급 기록 ${dropped}개 버림(V4 서명은 V5 회로에서 검증되지 않는다), 계정마다 creds:[] — 사용자 자격증명은 첫 로그인 때 다시 발급된다`);
  }
  if (state.version !== CIA_STATE_VERSION) throw new Error(`unsupported CIA state version ${state.version} (expected ${CIA_STATE_VERSION})`);
  state.accounts ??= {}; state.rps ??= {}; state.openings ??= []; state.revoked ??= []; state.pending ??= []; state.epoch ??= 0;
  for (const a of Object.values(state.accounts)) a.creds ??= [];
  return { state, notes };
}
