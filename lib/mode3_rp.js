// RP 검증기. 오프체인 검증기. 온체인 판은 contracts/Mode3Wallet.sol — 같은 순서·같은 규칙(2026-09-18 §5.3).
//
//   a. 체인 뷰 신선도   ← fail-closed (§8.5). 헤드 높이로 판단하므로 하트비트가 필요 없다
//   b. root 일치        ← N=1 (§8.2). 최신 root 가 아니면 거절
//   b′. root 게시 나이   ← head − lastPublishedBlock ≤ maxRootAge (2026-09-23 점검 C-1). 온체인 RootTooOld 와 같은 상한
//   r_s 는 공개 입력에 없다(2026-09-18 §2) — 서버가 자기가 준 챌린지를 넘기고 검증기는 σ 를 그 위에서 확인한다(f)
//   c. 만료             ← head ≤ max_height (블록 높이, 2026-09-18 §3.2). 체인 뷰의 head 를 쓴다
//   c'. chainid         ← credential 의 폐기 체인이 RP 가 읽는 체인과 같은가 (신규)
//   d. pk_CIA 고정      ← **유일한 위조 방어선** (§5). 회로는 "어떤 키에 대해" 만 증명한다
//      arid 일치        ← 다른 RP 용 credential 거절
//      pk_trace 일치    ← 자기 조합 키로 만든 태그인가 (2026-09-16 §4.3 d')
//      태그 형식        ← c1 이 항등원(r=0)이면 평문을 그대로 드러낸다 — bad_tag
//      allowAgent ≤ 1   ← 회로도 막지만 이벤트·세션에 남는 값이라 한 번 더
//      disc_mask < 16   ← 회로도 막지만 세션·로그에 남는 값이라 한 번 더(2026-09-22 §6.2) — bad_disclosure
//   e. Groth16
//   f. 챌린지 서명       ← 요청마다 새 σ (§8.4). pk_i 는 주소이므로 ethers.verifyMessage 로 복원
//   g. PPID
import { ethers } from 'ethers';
import * as snarkjs from 'snarkjs';
import { LOG_ABI } from './mode3_log.js';

export function createRpVerifier({ provider, logAddress, vkey, pkCIA, arid, chainId, pkTrace, headMaxAgeMs = 10 * 60_000, maxLifetimeBlocks = 400n, maxRootAge = 100n, now = Date.now }) {
  if (typeof maxLifetimeBlocks !== 'bigint' || maxLifetimeBlocks <= 0n) throw new Error('createRpVerifier: maxLifetimeBlocks(bigint > 0) 가 필요하다 — 지갑이 정한 max_height 의 상한(설계 2026-09-18 §3.2)');
  if (typeof maxRootAge !== 'bigint' || maxRootAge <= 0n) throw new Error('createRpVerifier: maxRootAge(bigint > 0) 가 필요하다 — 컨트랙트 maxRootAge 와 같은 값(2026-09-23 점검 C-1)');
  if (typeof chainId !== 'bigint') throw new Error('createRpVerifier: chainId(bigint) 가 필요하다 — RP 가 읽는 폐기 체인의 id');
  if (typeof pkTrace?.x !== 'bigint' || typeof pkTrace?.y !== 'bigint') throw new Error('createRpVerifier: pkTrace{x,y}(bigint) 가 필요하다 — 등록 파일의 조합 키');
  const log = new ethers.Contract(logAddress, LOG_ABI, provider);
  let view = null;   // { root, head, lastPublishedBlock, readAt }

  async function refreshChainView() {
    // ethers v6 는 getBlockNumber 를 250ms 캐시하지만 eth_call(root())은 캐시하지 않는다.
    // head 를 먼저 읽고 그 블록에 root 조회를 고정해야 root/head 가 같은 스냅샷이 된다
    // (lib/mode3_wallet.js 의 syncRevocationTree 와 같은 규칙). lastPublishedBlock 도 같은 블록에 고정한다 —
    // root 와 그 나이가 서로 다른 블록에서 오면 나이 판정이 어긋난다.
    const head = BigInt(await provider.getBlockNumber());
    const blockTag = Number(head);
    const [root, lastPublishedBlock] = await Promise.all([log.root({ blockTag }), log.lastPublishedBlock({ blockTag })]);
    view = { root: BigInt(root), head, lastPublishedBlock: BigInt(lastPublishedBlock), readAt: now() };
    return view;
  }
  async function chainView() {
    try { return await refreshChainView(); }
    catch {
      // RPC 실패: 10분 안의 캐시만 인정한다. 그보다 오래됐으면 폐기가 무력화될 수 있으니 거절.
      if (view && now() - view.readAt <= headMaxAgeMs) return view;
      return null;
    }
  }

  async function verifyLogin({ proof, publicSignals, sig, r_s }) {
    if (!Array.isArray(publicSignals) || publicSignals.length !== 25 || !proof || typeof sig !== 'string' || typeof r_s !== 'bigint') {
      return { ok: false, reason: 'malformed' };
    }
    // 공개 입력은 **정규 10진 문자열**이어야 한다(2026-09-25 전체 리뷰 C-1, Critical).
    // snarkjs 의 unstringifyBigInts 는 /^[0-9]+$/ 가 아닌 문자열을 BigInt 로 바꾸지 않고 그대로 두고,
    // Scalar.toRprLE 가 그 문자열에 .toString(16) 을 불러 **16진으로** 파싱한다(실측: " 1"→0, " 2000"→0, "2007 "→8199).
    // 그래서 이 검사가 없으면 아래 정책 검사(BigInt)와 groth16.verify 가 서로 다른 값을 본다 — 정상 로그인 π(mask=0)에
    // " 1"·" 2000" 을 실으면 증명은 통과하고 서비스는 "출생연도 ≤ 2000 을 공개했다" 고 믿는다(나이·집합·allowAgent 위조).
    if (!publicSignals.every((v) => typeof v === 'string' && /^[0-9]+$/.test(v))) return { ok: false, reason: 'malformed' };
    let ps;
    try { ps = publicSignals.map((s) => BigInt(s)); } catch { return { ok: false, reason: 'malformed' }; }
    const [PPID, aridIn, pk_i, max_height, chainIn, allowAgent, revRoot, ciaX, ciaY, traceX, traceY, c1x, c1y, c2, discMask, lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3, setSel, setRoot] = ps;
    const disclosure = maskDisclosure({ mask: discMask, lo: [lo0, lo1, lo2, lo3], hi: [hi0, hi1, hi2, hi3], sel: setSel, root: setRoot });

    const v = await chainView();                                   // a
    if (!v) return { ok: false, reason: 'chain_unavailable' };
    if (revRoot !== v.root) return { ok: false, reason: 'stale_root' };       // b
    // b′ — root 게시 나이(2026-09-23 점검 C-1). 온체인 execute 의 RootTooOld 와 같은 상한. CIA 가 게시(하트비트)를
    // 멈추면 오프체인 로그인도 같이 멈춘다 — 폐기가 체인에 못 오르는 동안 로그인이 계속되는 것을 막는다.
    if (v.head - v.lastPublishedBlock > maxRootAge) return { ok: false, reason: 'root_too_old' };
    if (v.head > max_height) return { ok: false, reason: 'expired' };         // c — 블록 높이
    if (max_height > v.head + maxLifetimeBlocks) return { ok: false, reason: 'bad_expiry' };   // c'' — 지갑이 정한 만료의 상한(L). 없으면 만료 없는 성명이 된다
    if (chainIn !== chainId) return { ok: false, reason: 'wrong_chain' };     // c'
    if (ciaX !== BigInt(pkCIA.x) || ciaY !== BigInt(pkCIA.y)) return { ok: false, reason: 'untrusted_cia' };   // d
    if (aridIn !== BigInt(arid)) return { ok: false, reason: 'wrong_arid' };  // d
    if (traceX !== pkTrace.x || traceY !== pkTrace.y) return { ok: false, reason: 'wrong_trace_key' };   // d'
    if (allowAgent > 1n) return { ok: false, reason: 'bad_allow_agent' };
    // r = 0 이면 c1 이 항등원이라 태그가 평문을 그대로 드러낸다 — 지갑 실수를 여기서 막는다.
    if (c1x === 0n && c1y === 1n) return { ok: false, reason: 'bad_tag' };
    if (discMask >= 16n) return { ok: false, reason: 'bad_disclosure' };   // 회로도 막지만 세션·로그에 남는 값이라 한 번 더(2026-09-22 §6.2)
    if (setSel > 4n || (setSel === 0n && setRoot !== 0n)) return { ok: false, reason: 'bad_disclosure' };   // V7 — 회로도 막지만 세션·로그에 남는 값이라 한 번 더

    let proofOk = false;                                           // e
    // 정규형(ps)을 넘긴다 — 위 형식 검사와 함께 이중 방어다. 원문을 넘기면 파싱이 갈릴 여지가 남는다(C-1).
    try { proofOk = await snarkjs.groth16.verify(vkey, ps.map(String), proof); } catch { proofOk = false; }
    if (!proofOk) return { ok: false, reason: 'bad_proof' };

    let signer;                                                    // f — σ 는 서버가 준 r_s(10진) 위
    try { signer = BigInt(ethers.verifyMessage(r_s.toString(), sig)); } catch { return { ok: false, reason: 'bad_signature' }; }
    if (signer !== pk_i) return { ok: false, reason: 'bad_signature' };

    // publicSignals 는 정규 10진 문자열로 돌려준다 — 서버는 이것을 기록·개봉에 써야 한다. 원문을 쓰면 앞자리 0 이 붙은
    // 입력이 로그인은 통과하고 개봉 때 CIA 의 문자열 비교·서명 재구성과 어긋나 그 세션을 영영 열 수 없게 된다(2026-09-18 점검 1).
    return { ok: true, PPID, pk_i, max_height, allowAgent, root: revRoot, tag: { c1x, c1y, c2 }, disclosure, publicSignals: ps.map(String) };  // g — 서버가 세션을 만든다
  }

  return { verifyLogin, refreshChainView };
}

/** mask 비트가 0 인 슬롯의 lo/hi 를 0 으로 지운다. 회로는 그 슬롯의 disc_lo/hi 에 64비트 범위 말고 아무 제약도 걸지 않으므로
 *  (2026-09-22 §4.3), 그 값을 세션·로그·화면에 실으면 "AA 가 보증한 공개"처럼 읽힌다(2026-09-23 점검 C-2). */
export function maskDisclosure({ mask, lo, hi, sel = 0n, root = 0n }) {
  if (!Array.isArray(lo) || !Array.isArray(hi) || lo.length !== 4 || hi.length !== 4) throw new Error('maskDisclosure: disclosure lo/hi 는 길이 4 여야 한다 — 슬롯 수(4)와 mask 비트가 어긋나면 엉뚱한 슬롯을 지운다');
  const m = BigInt(mask);
  const keep = (arr) => arr.map((v, k) => (((m >> BigInt(k)) & 1n) === 1n ? BigInt(v) : 0n));
  const s = BigInt(sel);
  return { mask: m, lo: keep(lo), hi: keep(hi), sel: s, root: s === 0n ? 0n : BigInt(root) };   // V7: sel 0 이면 root 는 무시되는 값 — 지운다
}

/** 세션 요청 σ 검증 (설계 §7). lib/mode3_wallet.js 의 signSessionRequest 와 메시지 규약을 공유한다. */
export function verifySessionRequest({ pk_i, r_s, body, sig }) {
  try { return BigInt(ethers.verifyMessage(`${r_s.toString()}:${body}`, sig)) === BigInt(pk_i); }
  catch { return false; }
}
