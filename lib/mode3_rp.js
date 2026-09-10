// RP 검증기 — 설계 §6.3 의 7단계를 그 순서대로. 오프체인 전용(§9.11).
//
//   a. 체인 뷰 신선도   ← fail-closed (§8.5). 헤드 높이로 판단하므로 하트비트가 필요 없다
//   b. root 일치        ← N=1 (§8.2). 최신 root 가 아니면 거절
//   c. 만료             ← head ≤ max_height. 온체인 §6.4 의 block.number 검사가 옮겨온 것
//   d. pk_CIA 고정      ← **유일한 위조 방어선** (§5). 회로는 "어떤 키에 대해" 만 증명한다
//      arid 일치        ← 다른 RP 용 credential 거절
//   e. Groth16
//   f. 챌린지 서명       ← 요청마다 새 σ (§8.4). pk_i 는 주소이므로 ethers.verifyMessage 로 복원
//   g. PPID
import { ethers } from 'ethers';
import * as snarkjs from 'snarkjs';

const LOG_ABI = ['function root() view returns (bytes32)'];

export function createRpVerifier({ provider, logAddress, vkey, pkCIA, arid, headMaxAgeMs = 10 * 60_000, now = Date.now }) {
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

  async function verifyLogin({ proof, publicSignals, challenge, sig }) {
    if (!Array.isArray(publicSignals) || publicSignals.length !== 7 || !proof || typeof challenge !== 'string' || typeof sig !== 'string') {
      return { ok: false, reason: 'malformed' };
    }
    let ps;
    try { ps = publicSignals.map((s) => BigInt(s)); } catch { return { ok: false, reason: 'malformed' }; }
    const [PPID, aridIn, pk_i, max_height, revRoot, ciaX, ciaY] = ps;

    const v = await chainView();                                   // a
    if (!v) return { ok: false, reason: 'chain_unavailable' };
    if (revRoot !== v.root) return { ok: false, reason: 'stale_root' };       // b
    if (v.head > max_height) return { ok: false, reason: 'expired' };          // c
    if (ciaX !== BigInt(pkCIA.x) || ciaY !== BigInt(pkCIA.y)) return { ok: false, reason: 'untrusted_cia' };   // d
    if (aridIn !== BigInt(arid)) return { ok: false, reason: 'wrong_arid' };

    let proofOk = false;                                           // e
    try { proofOk = await snarkjs.groth16.verify(vkey, publicSignals, proof); } catch { proofOk = false; }
    if (!proofOk) return { ok: false, reason: 'bad_proof' };

    let signer;                                                    // f
    try { signer = BigInt(ethers.verifyMessage(challenge, sig)); } catch { return { ok: false, reason: 'bad_signature' }; }
    if (signer !== pk_i) return { ok: false, reason: 'bad_signature' };

    return { ok: true, PPID, pk_i };                               // g
  }

  return { verifyLogin, refreshChainView };
}
