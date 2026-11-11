// lib/mode3_rp_accounts.js — RP 계정 저장소(스펙 2026-11-10-mode3-rp-social-logins §2). RP(mode3_rp.js)만 쓴다.
// 계정 하나에 로그인 수단 세 칸(zkid=PPID · google · naver) — 수단 하나는 계정 하나에만(색인 byPPID·byGoogle·byNaver). KRW 장부와 거래소 보관 ETH(wei)도
// 계정 번호 기준이다(어느 수단으로 로그인해도 같은 잔고). 파일 version 2. version 1(byPPID → { attrCommit, since, updatedAt, history }, 11-09 Phase 1)은
// 열 때 PPID 계정으로 옮긴다. 모르는 모양이면 기동을 막는다 — 조용히 비우면 장부를 잃는다.
import { randomBytes } from 'node:crypto';
import { readJson, writeJsonAtomic } from './mode3_state.js';

export const METHODS = Object.freeze(['zkid', 'google', 'naver']);
const INDEX = Object.freeze({ zkid: 'byPPID', google: 'byGoogle', naver: 'byNaver' });
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);

export class AccountError extends Error {
  constructor(status, reason) { super(reason); this.status = status; this.reason = reason; }
}
const fail = (status, reason) => { throw new AccountError(status, reason); };
/** 수단의 색인 키 — zkid 는 PPID(10진), google·naver 는 sub. */
function keyOf(method, ref) {
  if (!METHODS.includes(method)) fail(400, 'bad_method');
  if (method === 'zkid') { if (!isDec(ref?.PPID) || ref.PPID.length > 80) fail(400, 'bad_ppid'); return ref.PPID; }
  if (typeof ref?.sub !== 'string' || !ref.sub || ref.sub.length > 256) fail(400, 'bad_sub');
  return ref.sub;
}
const slotOf = (method, k, at) => (method === 'zkid' ? { PPID: k, linkedAt: at } : { sub: k, linkedAt: at });
export const emptyAccountsState = () => ({ version: 2, accounts: {}, byPPID: {}, byGoogle: {}, byNaver: {}, krw: {}, custodyEth: {} });
const blankAccount = (id, at) => ({ id, createdAt: at, zkid: null, google: null, naver: null });
// 2026-11-11(사용자 결정): RP 는 사용자 속성 커밋먼트(C_attr)를 갖지 않는다 — 11-09 Phase 1 이 계정에 고정하던 칸. 옛 파일에 남았으면 열 때 지운다.
const ATTR_FIELDS = ['attrCommit', 'attrSince', 'attrUpdatedAt', 'attrHistory'];
/** 계정들에서 attr 칸을 지운다. 지운 것이 있으면 true(호출자가 파일을 다시 쓴다). */
function dropAttrFields(accounts) {
  let dropped = false;
  for (const a of Object.values(accounts)) for (const k of ATTR_FIELDS) if (a && k in a) { delete a[k]; dropped = true; }
  return dropped;
}

/** 파일 내용 → version 2 상태. migrated 면 호출자가 곧바로 다시 쓴다. */
export function migrateAccounts(raw, { now, newId }) {
  if (raw === null || raw === undefined) return { state: emptyAccountsState(), migrated: false };
  if (raw.version === 2 && raw.accounts && typeof raw.accounts === 'object') { const state = { ...emptyAccountsState(), ...raw }; return { state, migrated: dropAttrFields(state.accounts) }; }
  if (raw.version === 1 && raw.byPPID && typeof raw.byPPID === 'object') {
    const s = emptyAccountsState();
    for (const [PPID, v] of Object.entries(raw.byPPID)) {
      if (!isDec(PPID)) continue;
      const id = newId(), at = v?.since ?? now;
      s.accounts[id] = { ...blankAccount(id, at), zkid: { PPID, linkedAt: at } };   // 옛 커밋먼트는 옮기지 않는다(2026-11-11)
      s.byPPID[PPID] = id;
    }
    return { state: s, migrated: true };
  }
  throw new Error('RP 계정 파일의 모양을 모른다(version 1·2 가 아니다) — 지우지 말고 확인할 것');
}

export function openAccountStore({ file, now = () => new Date().toISOString(), newId = () => `acct_${randomBytes(8).toString('hex')}` }) {
  const { state, migrated } = migrateAccounts(readJson(file, null), { now: now(), newId });
  const save = () => writeJsonAtomic(file, state, 0o600);
  if (migrated) save();
  const acct = (id) => state.accounts[id] ?? fail(404, 'no_account');
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const store = {
    get: (id) => (state.accounts[id] ? clone(state.accounts[id]) : null),
    findBy: (method, ref) => state[INDEX[method] ?? fail(400, 'bad_method')][keyOf(method, ref)] ?? null,
    /** 그 수단의 계정으로 로그인 — 없으면 그 칸만 채운 새 계정을 만든다(R4). */
    loginOrCreate(method, ref) {
      const k = keyOf(method, ref);
      const found = state[INDEX[method]][k];
      if (found) return { id: found, created: false };
      const id = newId(), at = now();
      state.accounts[id] = { ...blankAccount(id, at), [method]: slotOf(method, k, at) };
      state[INDEX[method]][k] = id;
      save();
      return { id, created: true };
    },
    /** 로그인한 계정의 빈 칸에 붙인다 — 병합은 하지 않는다. */
    link(id, method, ref) {
      const a = acct(id), k = keyOf(method, ref);
      const owner = state[INDEX[method]][k];
      if (owner === id) return clone(a);
      if (owner) fail(409, 'method_linked_elsewhere');
      if (a[method]) fail(409, 'method_already_linked');
      a[method] = slotOf(method, k, now());
      state[INDEX[method]][k] = id;
      save();
      return clone(a);
    },
    /** 수단이 하나 이상 남을 때만 푼다. */
    unlink(id, method) {
      const a = acct(id);
      if (!METHODS.includes(method)) fail(400, 'bad_method');
      if (!a[method]) fail(409, 'not_linked');
      if (METHODS.filter((m) => a[m]).length <= 1) fail(409, 'last_method');
      delete state[INDEX[method]][method === 'zkid' ? a.zkid.PPID : a[method].sub];
      a[method] = null;
      save();
      return clone(a);
    },
    /** 화면·API 용 — Google·네이버 sub 은 싣지 않는다. */
    view(id) {
      const a = acct(id);
      return { account: id, methods: { zkid: a.zkid ? { PPID: a.zkid.PPID, linkedAt: a.zkid.linkedAt } : null, google: a.google ? { linkedAt: a.google.linkedAt } : null, naver: a.naver ? { linkedAt: a.naver.linkedAt } : null } };
    },
    krw: (id) => BigInt(state.krw[id] ?? '0'),
    custody: (id) => BigInt(state.custodyEth[id] ?? '0'),
    /** 장부 증감 — 결과가 음수면 400 이고 아무것도 바꾸지 않는다. */
    addKrw(id, delta) { acct(id); const v = store.krw(id) + BigInt(delta); if (v < 0n) fail(400, 'insufficient_krw'); state.krw[id] = v.toString(); save(); return v; },
    addCustody(id, delta) { acct(id); const v = store.custody(id) + BigInt(delta); if (v < 0n) fail(400, 'insufficient_custody'); state.custodyEth[id] = v.toString(); save(); return v; },
  };
  return store;
}
