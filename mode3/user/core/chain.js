// mode3/user/core/chain.js — 거울 뷰 동기화(V10 규칙, mode3_wallet_agent.js syncAll 과 같다). 증분 체크포인트는 없다(계획 R2): 두 트리를 창세기부터 재생한다.
import { ethers } from 'ethers';
import { syncRevocationTree, syncRegistryTree } from '../../../lib/mode3_wallet.js';
import { MODE3_ROOTS_ABI } from '../../../lib/mode3_log.js';
import { factoryAt } from '../../../lib/mode3_onchain.js';
const tagged = (reason, msg) => Object.assign(new Error(msg ?? reason), { reason });
export function createChain({ provider, canonProvider = provider, logAddress, mirrorAddress }) {
  const mirror = mirrorAddress ? new ethers.Contract(mirrorAddress, MODE3_ROOTS_ABI, provider) : null;
  let chainIdCache = null; const acct = new Map();
  const missing = () => (!logAddress ? 'CIA_LOG_ADDRESS not configured' : !mirrorAddress ? 'MODE3_MIRROR_ADDRESS not configured' : null);
  const c = {
    missing,
    async chainId() { if (chainIdCache === null) chainIdCache = (await provider.getNetwork()).chainId; return chainIdCache; },
    async head() { return BigInt(await provider.getBlockNumber()); },
    /** 대상 체인 거울의 네 값을 한 블록(head)에서 읽는다 — 서로 다른 블록의 revRoot·regRoot 를 짝짓지 않게. */
    async mirrorView() {
      const head = await c.head(); const blockTag = Number(head);
      const [revRoot, regRoot, epoch, last] = await Promise.all([mirror.revRoot({ blockTag }), mirror.regRoot({ blockTag }), mirror.epoch({ blockTag }), mirror.lastPublishedBlock({ blockTag })]);
      return { root: BigInt(revRoot), regRoot: BigInt(regRoot), epoch: BigInt(epoch), head, lastPublishedBlock: BigInt(last) };
    },
    /** 에이전트 syncAll 과 같은 반환 모양. RPC 실패는 chain_unavailable, 거울·캐노니컬 불일치는 sync_unstable 로 태그한다.
     *  두 트리를 그냥 병렬로 동기화하면 그 사이 IdP 의 게시가 끼어들어 한 번도 온체인에 같이 존재한 적 없는 (revRoot, regRoot) 쌍이
     *  나올 수 있다 — 순차로 동기화해 head 가 같아질 때까지 최대 3 번. 돌려주는 root·regRoot·epoch·tree·registry 는 **거울 뷰**다
     *  (RP·계정 컨트랙트가 거울만 읽는다). canonical 은 캐노니컬 최신 — 내 슬롯 확인·세션 폐기 사전 확인용. */
    async syncAll() {
      const m = missing(); if (m) throw tagged('chain_unavailable', m);
      let mv, rev = null, reg = null;
      try {
        mv = await c.mirrorView();
        for (let i = 0; i < 3; i++) { rev = await syncRevocationTree(canonProvider, logAddress); reg = await syncRegistryTree(canonProvider, logAddress); if (BigInt(rev.head) === BigInt(reg.head)) break; rev = null; }
      } catch (e) { if (e.reason) throw e; throw tagged('chain_unavailable', e.shortMessage ?? e.message); }
      if (!rev) throw tagged('sync_unstable');
      const canonical = { root: rev.root, regRoot: reg.root, epoch: reg.epoch, tree: rev.tree, registry: reg.tree };
      // 거울이 캐노니컬보다 앞설 수는 없다(거울은 캐노니컬에 게시된 서명만 받는다) — 그렇게 보이면 두 RPC 가 서로 다른 캐노니컬 로그를 보고 있다.
      if (mv.epoch > canonical.epoch) throw tagged('sync_unstable', `sync_unstable: 거울 epoch(${mv.epoch}) 가 캐노니컬 epoch(${canonical.epoch}) 보다 앞서 있다`);
      let tree = rev.tree, registry = reg.tree;
      if (rev.root !== mv.root || reg.root !== mv.regRoot) {
        // 거울이 뒤처져 있다 — 거울 epoch 시점의 트리로 되감는다(fail-closed: 재생 root 가 거울과 다르면 던진다).
        try { ({ tree, registry } = await c.replayAt(mv.epoch, mv.root, mv.regRoot)); } catch (e) { throw tagged('sync_unstable', e.message); }
      }
      return { root: mv.root, regRoot: mv.regRoot, epoch: mv.epoch, head: mv.head, tree, registry, chainId: await c.chainId(), mirror: { lastPublishedBlock: mv.lastPublishedBlock }, canonical };
    },
    /** 캐노니컬 이벤트를 epoch 까지만 재생해 (revRoot, regRoot) 와 대조한 두 트리. 맞지 않으면 미태그 Error. */
    async replayAt(epoch, revRoot, regRoot) {
      const [rev, reg] = await Promise.all([
        syncRevocationTree(canonProvider, logAddress, { untilEpoch: epoch, expectRoot: revRoot }),
        syncRegistryTree(canonProvider, logAddress, { untilEpoch: epoch, expectRoot: regRoot }),
      ]);
      return { tree: rev.tree, registry: reg.tree };
    },
    /** PPID 계정 주소(팩토리 computeAddress) — (factory, PPID) 별 캐시. RPC 실패면 null(표기만 비운다). */
    async accountAddressOf(factoryAddress, PPID) {
      const k = `${factoryAddress}:${PPID}`; if (acct.has(k)) return acct.get(k);
      try { const a = await factoryAt(factoryAddress, provider).computeAddress(BigInt(PPID)); acct.set(k, a); return a; } catch { return null; }
    },
    factory: (address) => factoryAt(address, provider),
  };
  return c;
}
