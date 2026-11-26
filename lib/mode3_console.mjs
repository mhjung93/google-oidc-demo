// 체인 콘솔의 도우미(2026-11-26, 피드백 "버튼 딸깍으로 보이지 말고, 콘솔에서 트랜잭션을 내며 전 거래의 ZKP 를 복사해 root 만 바꿔 보여라").
// scripts/mode3_console.mjs 가 대화형 콘솔에 올려 두고, 시연자가 한 줄씩 부른다. 키는 쓰지 않는다 — 체인에 남은 값과 노드의 개발 계정(보낼 때만)뿐이다.
// 계정 컨트랙트(Mode3Wallet)의 execute 는 nonce → 세션키 서명 → root 창 → 증명 순서로 본다. 그래서 남의 거래를 그대로 다시 보내면 증명까지 가기 전에
// NonceMismatch 로 막히고, "증명이 root 에 묶여 있다" 는 체인의 검증 컨트랙트(PiCredVerifier.verifyProof)를 직접 불러 보인다.
import { ethers } from 'ethers';
import { walletInterface, decodeExecuteCalldata, PUB_INDEX } from './mode3_onchain.js';

const ACCOUNT_LINKS_ABI = ['function verifier() view returns (address)', 'function log() view returns (address)'];
const VERIFIER_ABI = ['function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[29] pub) view returns (bool)'];
const ROOTS_ABI = ['function revRoot() view returns (bytes32)', 'function regRoot() view returns (bytes32)'];
export const PUB_NAMES = Object.freeze(Object.fromEntries(Object.entries(PUB_INDEX).map(([k, v]) => [v, k])));
const EXECUTE_SELECTOR = walletInterface.getFunction('execute').selector;
const SEND_GAS = 1_500_000n;   // 되돌려질 거래도 블록에 남기려고 가스 추정을 건너뛴다

/** 되돌림 오류의 이름과 인자 — 계정 컨트랙트의 오류면 NonceMismatch(…) 처럼, 아니면 노드의 문구. */
export function revertText(e) {
  const data = e?.data ?? e?.info?.error?.data?.data ?? e?.error?.data?.data ?? e?.info?.error?.data ?? null;
  if (typeof data === 'string' && data.startsWith('0x') && data.length >= 10) {
    try { const p = walletInterface.parseError(data); if (p) return `${p.name}(${p.args.map(String).join(', ')})`; } catch { /* 모르는 오류 */ }
  }
  return e?.revert?.name ?? e?.shortMessage ?? e?.message ?? 'revert';
}

/**
 * provider: ethers JsonRpcProvider, signer: 보낼 때 쓸 노드의 개발 계정(없으면 send 를 쓰지 못한다), explorer: 탐색기 주소(링크 표시용).
 * 돌려주는 도우미는 모두 async 다 — 콘솔에서 await 로 부른다.
 */
export function createConsoleHelpers({ provider, signer = null, explorer = null }) {
  /** 거래 해시 → { hash, account(계정 주소), block, payload, sig, a, b, c, pub(29개, 10진 문자열) }. execute 거래가 아니면 오류. */
  async function tx(hash) {
    const t = await provider.getTransaction(hash);
    if (!t) throw new Error(`거래가 없다: ${hash}`);
    const d = decodeExecuteCalldata(t.data);
    if (!d) throw new Error('계정 컨트랙트의 execute 거래가 아니다');
    return { hash: t.hash, account: t.to, block: t.blockNumber, ...d };
  }
  /** 최근 blocks 블록 안에서 가장 최근의 execute 거래(성공한 것만, account 를 주면 그 계정 것만). 없으면 null. */
  async function last({ blocks = 500, account = null } = {}) {
    const head = await provider.getBlockNumber();
    for (let n = head; n >= Math.max(0, head - blocks); n--) {
      const b = await provider.getBlock(n, true);
      for (const t of [...(b?.prefetchedTransactions ?? [])].reverse()) {
        if (!t.data?.startsWith(EXECUTE_SELECTOR) || (account && t.to?.toLowerCase() !== account.toLowerCase())) continue;
        const rc = await provider.getTransactionReceipt(t.hash);
        if (rc?.status === 1) return tx(t.hash);
      }
    }
    return null;
  }
  /** 공개 입력 29개를 이름과 함께 한 줄씩. */
  function show(x) { return x.pub.map((v, i) => `[${String(i).padStart(2)}] ${(PUB_NAMES[i] ?? '').padEnd(12)} ${v}`).join('\n'); }
  async function linked(x) { return new ethers.Contract(x.account, ACCOUNT_LINKS_ABI, provider); }
  /** 그 계정이 쓰는 검증 컨트랙트로 증명을 검사한다 — pub 를 주면 그 공개 입력으로(증명 a·b·c 는 x 의 것 그대로). */
  async function verify(x, pub = x.pub) {
    const v = new ethers.Contract(await (await linked(x)).verifier(), VERIFIER_ABI, provider);
    return v.verifyProof(x.a, x.b, x.c, pub);
  }
  /** 지금 체인의 root(그 계정이 보는 거울)와 증명에 든 root. 모두 10진 문자열. */
  async function roots(x) {
    const log = new ethers.Contract(await (await linked(x)).log(), ROOTS_ABI, provider);
    return { revRootNow: BigInt(await log.revRoot()).toString(), revRootInProof: x.pub[PUB_INDEX.REV_ROOT], regRootNow: BigInt(await log.regRoot()).toString(), regRootInProof: x.pub[PUB_INDEX.REG_ROOT] };
  }
  /** x 의 사본 — 증명·서명·payload 는 그대로, 공개 입력의 폐기 목록 root(pub[6])만 바꾼다. */
  function withRoot(x, root) { const pub = [...x.pub]; pub[PUB_INDEX.REV_ROOT] = BigInt(root).toString(); return { ...x, pub }; }
  /** x 의 인자로 execute 를 실제 거래로 보낸다(노드의 개발 계정). 되돌려져도 블록에 남는다 → { hash, status, reason, block, link }. */
  async function send(x) {
    if (!signer) throw new Error('보낼 계정이 없다');
    const data = walletInterface.encodeFunctionData('execute', [x.payload, x.sig, x.a, x.b, x.c, x.pub]);
    const from = await signer.getAddress();
    let reason = null;
    try { await provider.call({ from, to: x.account, data }); } catch (e) { reason = revertText(e); }
    let hash;
    try { hash = (await signer.sendTransaction({ to: x.account, data, gasLimit: SEND_GAS })).hash; }
    catch (e) {
      // hardhat 은 자동 채굴에서 되돌려진 거래도 블록에 넣고 eth_sendTransaction 에 오류로 답한다 — 오류에 실린 해시를 꺼낸다(mode3_rp.js sendRevertingTx 와 같다)
      let dump = ''; try { dump = JSON.stringify(e, (k, v) => (typeof v === 'bigint' ? v.toString() : v)); } catch { throw e; }
      hash = dump.match(/"(?:txHash|transactionHash)":"(0x[0-9a-fA-F]{64})"/)?.[1];
      if (!hash) throw e;
      reason ??= revertText(e);
    }
    const rc = await provider.waitForTransaction(hash);
    return { hash, status: rc?.status === 1 ? 'success' : 'reverted', reason, block: rc?.blockNumber ?? null, link: explorer ? `${explorer}/tx/${hash}` : null };
  }
  return { tx, last, show, verify, roots, withRoot, send };
}
