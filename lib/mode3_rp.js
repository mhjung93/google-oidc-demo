// RP 검증기. 오프체인 검증기. 온체인 판은 contracts/Mode3Wallet.sol — 같은 순서·같은 규칙(2026-09-18 §5.3).
//
//   a. 체인 뷰 신선도   ← fail-closed (§8.5). 헤드 높이로 판단하므로 하트비트가 필요 없다
//   b. root 일치        ← N=1 (§8.2). 최신 root 가 아니면 거절
//   r_s 는 공개 입력에 없다(2026-09-18 §2) — 서버가 자기가 준 챌린지를 넘기고 검증기는 σ 를 그 위에서 확인한다(f)
//   c. 만료             ← head ≤ max_height (블록 높이, 2026-09-18 §3.2). 체인 뷰의 head 를 쓴다
//   c'. chainid         ← credential 의 폐기 체인이 RP 가 읽는 체인과 같은가 (신규)
//   d. pk_CIA 고정      ← **유일한 위조 방어선** (§5). 회로는 "어떤 키에 대해" 만 증명한다
//      arid 일치        ← 다른 RP 용 credential 거절
//      pk_trace 일치    ← 자기 조합 키로 만든 태그인가 (2026-09-16 §4.3 d')
//      태그 형식        ← c1 이 항등원(r=0)이면 평문을 그대로 드러낸다 — bad_tag
//      allowAgent ≤ 1   ← 회로도 막지만 이벤트·세션에 남는 값이라 한 번 더
//   e. Groth16
//   f. 챌린지 서명       ← 요청마다 새 σ (§8.4). pk_i 는 주소이므로 ethers.verifyMessage 로 복원
//   g. PPID
import { ethers } from 'ethers';
import * as snarkjs from 'snarkjs';
import { LOG_ABI } from './mode3_log.js';

export function createRpVerifier({ provider, logAddress, vkey, pkCIA, arid, chainId, pkTrace, headMaxAgeMs = 10 * 60_000, now = Date.now }) {
  if (typeof chainId !== 'bigint') throw new Error('createRpVerifier: chainId(bigint) 가 필요하다 — RP 가 읽는 폐기 체인의 id');
  if (typeof pkTrace?.x !== 'bigint' || typeof pkTrace?.y !== 'bigint') throw new Error('createRpVerifier: pkTrace{x,y}(bigint) 가 필요하다 — 등록 파일의 조합 키');
  const log = new ethers.Contract(logAddress, LOG_ABI, provider);
  let view = null;   // { root, head, readAt }

  async function refreshChainView() {
    // ethers v6 는 getBlockNumber 를 250ms 캐시하지만 eth_call(root())은 캐시하지 않는다.
    // head 를 먼저 읽고 그 블록에 root 조회를 고정해야 root/head 가 같은 스냅샷이 된다
    // (lib/mode3_wallet.js 의 syncRevocationTree 와 같은 규칙).
    const head = BigInt(await provider.getBlockNumber());
    const root = BigInt(await log.root({ blockTag: Number(head) }));
    view = { root, head, readAt: now() };
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
    if (!Array.isArray(publicSignals) || publicSignals.length !== 14 || !proof || typeof sig !== 'string' || typeof r_s !== 'bigint') {
      return { ok: false, reason: 'malformed' };
    }
    let ps;
    try { ps = publicSignals.map((s) => BigInt(s)); } catch { return { ok: false, reason: 'malformed' }; }
    const [PPID, aridIn, pk_i, max_height, chainIn, allowAgent, revRoot, ciaX, ciaY, traceX, traceY, c1x, c1y, c2] = ps;

    const v = await chainView();                                   // a
    if (!v) return { ok: false, reason: 'chain_unavailable' };
    if (revRoot !== v.root) return { ok: false, reason: 'stale_root' };       // b
    if (v.head > max_height) return { ok: false, reason: 'expired' };         // c — 블록 높이
    if (chainIn !== chainId) return { ok: false, reason: 'wrong_chain' };     // c'
    if (ciaX !== BigInt(pkCIA.x) || ciaY !== BigInt(pkCIA.y)) return { ok: false, reason: 'untrusted_cia' };   // d
    if (aridIn !== BigInt(arid)) return { ok: false, reason: 'wrong_arid' };  // d
    if (traceX !== pkTrace.x || traceY !== pkTrace.y) return { ok: false, reason: 'wrong_trace_key' };   // d'
    if (allowAgent > 1n) return { ok: false, reason: 'bad_allow_agent' };
    // r = 0 이면 c1 이 항등원이라 태그가 평문을 그대로 드러낸다 — 지갑 실수를 여기서 막는다.
    if (c1x === 0n && c1y === 1n) return { ok: false, reason: 'bad_tag' };

    let proofOk = false;                                           // e
    try { proofOk = await snarkjs.groth16.verify(vkey, publicSignals, proof); } catch { proofOk = false; }
    if (!proofOk) return { ok: false, reason: 'bad_proof' };

    let signer;                                                    // f — σ 는 서버가 준 r_s(10진) 위
    try { signer = BigInt(ethers.verifyMessage(r_s.toString(), sig)); } catch { return { ok: false, reason: 'bad_signature' }; }
    if (signer !== pk_i) return { ok: false, reason: 'bad_signature' };

    // publicSignals 는 정규 10진 문자열로 돌려준다 — 서버는 이것을 기록·개봉에 써야 한다. 원문을 쓰면 앞자리 0 이 붙은
    // 입력이 로그인은 통과하고 개봉 때 CIA 의 문자열 비교·서명 재구성과 어긋나 그 세션을 영영 열 수 없게 된다(2026-09-18 점검 1).
    return { ok: true, PPID, pk_i, max_height, allowAgent, root: revRoot, tag: { c1x, c1y, c2 }, publicSignals: ps.map(String) };  // g — 서버가 세션을 만든다
  }

  return { verifyLogin, refreshChainView };
}

/** 세션 요청 σ 검증 (설계 §7). lib/mode3_wallet.js 의 signSessionRequest 와 메시지 규약을 공유한다. */
export function verifySessionRequest({ pk_i, r_s, body, sig }) {
  try { return BigInt(ethers.verifyMessage(`${r_s.toString()}:${body}`, sig)) === BigInt(pk_i); }
  catch { return false; }
}
