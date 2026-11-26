// 체인 콘솔의 도우미(2026-11-26, 피드백 "버튼 딸깍으로 보이지 말고, 콘솔에서 트랜잭션을 내며 전 거래의 ZKP 를 복사해 root 만 바꿔 보여라").
// scripts/mode3_console.mjs 가 대화형 콘솔에 올려 두고, 시연자가 한 줄씩 부른다. 키는 쓰지 않는다 — 체인에 남은 값과 노드의 개발 계정(보낼 때만)뿐이다.
// 계정 컨트랙트(Mode3Wallet)의 execute 는 nonce → 세션키 서명 → root 창 → 증명 순서로 본다. 그래서 남의 거래를 그대로 다시 보내면 증명까지 가기 전에
// NonceMismatch 로 막히고, "증명이 root 에 묶여 있다" 는 체인의 검증 컨트랙트(PiCredVerifier.verifyProof)를 직접 불러 보인다.
import { ethers } from 'ethers';
import { walletInterface, decodeExecuteCalldata, PUB_INDEX } from './mode3_onchain.js';
import { traceRegistryAt, listOpenRequests } from './mode3_trace_chain.js';

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
 * traceRegistry: 추적 기록 등록부의 주소(2026-11-26 — 있으면 traceRecord·traceRequests·traceRequest 가 함께 온다).
 * 돌려주는 도우미는 모두 async 다 — 콘솔에서 await 로 부른다.
 */
export function createConsoleHelpers({ provider, signer = null, explorer = null, traceRegistry = null }) {
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
    // 영수증은 기한을 두고 직접 묻는다 — waitForTransaction 은 블록 이벤트를 기다려, 이미 채굴된 거래를 놓치면 끝나지 않는다(2026-11-26 테스트가 1시간 멈췄다)
    let rc = null;
    for (let i = 0; i < 60 && !rc; i++) { rc = await provider.getTransactionReceipt(hash); if (!rc) await new Promise((r) => setTimeout(r, 250)); }
    if (!rc) return { hash, status: 'pending', reason, block: null, link: explorer ? `${explorer}/tx/${hash}` : null };
    return { hash, status: rc?.status === 1 ? 'success' : 'reverted', reason, block: rc?.blockNumber ?? null, link: explorer ? `${explorer}/tx/${hash}` : null };
  }
  const link = (hash) => (explorer ? `${explorer}/tx/${hash}` : null);
  /** 영수증을 기한(15초)을 두고 직접 묻는다 — send 와 같은 이유. */
  async function receiptOf(hash) { for (let i = 0; i < 60; i++) { const rc = await provider.getTransactionReceipt(hash); if (rc) return rc; await new Promise((r) => setTimeout(r, 250)); } return null; }
  // ---- 추적 기록(스펙 2026-11-26 ppid-account-trace): 체인에 있는 것은 잠긴 값뿐이고, 여는 길은 체인의 요청 거래에서 시작한다는 것을 버튼 없이 보인다 ----
  const registry = () => { if (!traceRegistry) throw new Error('추적 기록 등록부 주소가 없다(TRACE_REGISTRY)'); return traceRegistryAt(traceRegistry, provider); };
  /** 그 PPID 의 추적 기록 — 체인에 있는 그대로({ ppid, arid, c1x, c1y, c2, registeredAt }: 감사자 키로 잠근 값이라 이것만으로는 누구인지 알 수 없다). 없으면 null. x(tx·last 의 결과)를 줘도 된다. */
  async function traceRecord(ppidOrX) {
    const ppid = BigInt(ppidOrX?.pub ? ppidOrX.pub[PUB_INDEX.PPID] : ppidOrX), reg = registry();
    if (!(await reg.has(ppid))) return null;
    const r = await reg.recordOf(ppid);
    return { ppid: ppid.toString(), arid: r.arid.toString(), c1x: r.c1x.toString(), c1y: r.c1y.toString(), c2: r.c2.toString(), registeredAt: Number(r.registeredAt) };
  }
  /** 등록부의 개봉 요청들 — { id, ppid, requester, reasonHash, requestedAt, shares:[응답한 감사자] }. */
  async function traceRequests() { return listOpenRequests(registry()); }
  /** 그 PPID 의 개봉을 요청하는 거래를 이 콘솔의 계정으로 낸다 → { hash, status, id, requester, link }. 누구나 낼 수 있지만 거래가 체인에 남고, 그 사용자의 화면("개봉 알림")에 뜬다. */
  async function traceRequest(ppidOrX, reason = '콘솔 시연') {
    if (!signer) throw new Error('보낼 계정이 없다');
    if (typeof reason !== 'string' || !reason.trim()) throw new Error('사유(문자열)가 필요하다');
    const ppid = BigInt(ppidOrX?.pub ? ppidOrX.pub[PUB_INDEX.PPID] : ppidOrX), reg = registry();
    if (!(await reg.has(ppid))) throw new Error('그 PPID 의 추적 기록이 없다');
    const hash = (await reg.connect(signer).requestOpen(ppid, ethers.id(reason))).hash, rc = await receiptOf(hash);
    const ev = rc?.logs.map((l) => { try { return reg.interface.parseLog(l); } catch { return null; } }).find((x) => x?.name === 'OpenRequested');
    return { hash, status: !rc ? 'pending' : rc.status === 1 ? 'success' : 'reverted', id: ev ? Number(ev.args.id) : null, requester: await signer.getAddress(), link: link(hash) };
  }
  return { tx, last, show, verify, roots, withRoot, send, ...(traceRegistry ? { traceRecord, traceRequests, traceRequest } : {}) };
}
