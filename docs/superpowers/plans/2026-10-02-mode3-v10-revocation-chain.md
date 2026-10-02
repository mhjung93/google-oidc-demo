# Mode 3 V10 — 폐기 전용 체인과 체인별 거울 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 폐기 상태(세션 폐기 root·등록부 root)의 정본을 폐기 체인의 `Mode3Log` V3 하나에 두고, 응용 체인은 `Mode3Mirror` 가 하트비트 주기로 받아 적은 값만 믿게 하며, 사용자의 폐기 요청은 IdP 서명 접수증을 폐기 체인 대기열에 올려 다음 게시를 강제할 수 있게 한다.

**Architecture:** 컨트랙트는 (1) 캐노니컬 `Mode3Log` V3(다이제스트가 `block.chainid`·`address(this)` 를 덮고, 접수증 대기열·은퇴 슬롯 잠금을 가짐), (2) `Mode3Mirror`(root 2개·epoch·lastPublishedBlock 만, 같은 IdP 서명으로 갱신), (3) 둘이 공유하는 읽기 인터페이스 `IMode3Roots`(`Mode3Wallet` 은 이것만 본다) 셋이다. CIA 는 캐노니컬에 게시하고, 체인별 릴레이 루프가 거울을 하트비트 주기로 갱신하며, 폐기 응답에 접수증을 싣는다. 지갑은 트리를 캐노니컬 이벤트로 재구성하되 증명의 root 는 대상 체인 거울의 (revRoot, regRoot, epoch) 를 따른다. RP 는 자기 체인 거울만 읽는다. 회로·증명·`Mode3Wallet` 의 검사 논리는 바뀌지 않는다.

**Tech Stack:** Solidity 0.8.24 + hardhat(인프로세스 체인은 `contract` 그룹, :8545 노드는 `chain` 그룹), ethers v6, Node 22 ESM, 기존 테스트 양식(`test/*.test.mjs` 는 mocha/chai, `tests/*.mjs` 는 `t(name, fn)` 스크립트).

**Spec:** `docs/superpowers/specs/2026-10-02-mode3-revocation-chain-design.md` (결정 1·2·3 과 §6 변경 범위가 이 계획의 근거다.)

## Global Constraints

- 회로(`circuits/mode3/pi_cred.circom`)·`build/mode3/` 산출물·`PiCredVerifier.sol`·공개 입력 30개 순서는 **건드리지 않는다**(스펙 §6 "변경 없음").
- `Mode3Wallet._checkStatement` 의 검사 순서·오류 이름(`StaleRevocationRoot`, `StaleRegistryRoot`, `RootTooOld`)은 그대로다. 바뀌는 것은 `log` 의 타입(`IMode3Roots`)뿐이다.
- 캐노니컬 다이제스트: `keccak256(abi.encode(DOMAIN, canonicalChainId, canonicalLogAddress, newRev, newReg, newEpoch, keccak(revLeaves), keccak(slotIdx), keccak(slotLeaves)))`, `DOMAIN = keccak256("MODE3_LOG_V3")`, EIP-191 personal_sign, low-s·v∈{27,28}(V2 와 같은 `_recover`). `slotIdx` 는 32바이트 패딩 패킹(V2 주석의 함정 그대로).
- 접수증 다이제스트: `keccak256(abi.encode(D_RECEIPT, canonicalChainId, canonicalLogAddress, slot, epochAtRequest, requestedAt))`, `D_RECEIPT = keccak256("MODE3_REVOKE_RECEIPT_V1")`, EIP-191. uid 는 넣지 않는다.
- 거울·캐노니컬 모두 `newEpoch > epoch` 만 요구한다(건너뜀 허용). 거울은 리프·슬롯 배열 대신 세 해시만 받는다.
- 대기열을 거쳐 0 이 된 슬롯은 영구 은퇴(캐노니컬이 0 아닌 갱신을 `SlotRetired` 로 거절). IdP 가 자발적으로 0 으로 만든 슬롯은 재사용 가능.
- 세션 폐기(`/cia/revoke scope=session`)는 바꾸지 않는다.
- 각 체인의 검증자(RP, `Mode3Wallet`)는 **자기 체인 거울 값만** 본다. 거울 갱신은 하트비트 주기(`CIA_MIRROR_HEARTBEAT_BLOCKS`, 기본 50)로만. `MAX_ROOT_AGE`(기본 100) ≥ 2·주기.
- 환경 변수 이름(새 것): `CIA_RPC_URL` = **폐기 체인** RPC(캐노니컬이 사는 곳, 의미 변경), `CIA_LOG_ADDRESS` = 캐노니컬 `Mode3Log` 주소(그대로), `CIA_MIRRORS` = `chainid=mirrorAddress[,…]`(RPC 는 기존 `CIA_CHAIN_RPCS` 의 `chainid=url` 에서), `CIA_MIRROR_HEARTBEAT_BLOCKS`(기본 50, 0 이면 릴레이 끔), `CIA_MIRROR_POLL_MS`(기본 5000). RP·지갑: `MODE3_MIRROR_ADDRESS`(자기 체인 거울), `MODE3_REV_CHAIN_RPC`(지갑만, 캐노니컬 RPC; 기본 `CIA_RPC_URL`). `CIA_HEARTBEAT_BLOCKS` 는 캐노니컬 하트비트로 의미 유지.
- 테스트는 **:8545 노드 하나**에 캐노니컬 로그와 거울을 둘 다 배포한다(두 컨트랙트, 같은 체인 — `canonicalChainId = 31337`). 두 번째 노드는 데모 런북에서만 선택 사항이다.
- 기존 규칙 유지: 상태 파일 삭제 금지, `.env` 읽기 금지, 새 테스트는 `scripts/run_tests.sh` 의 그룹에 넣는다, 커밋은 사용자 승인 뒤(계획의 "Commit" 단계는 메시지 제안이다 — SDD 실행 때 사용자가 커밋을 허용했으면 그대로 수행).
- 상태 파일 버전: CIA v9 → **v10**(`accounts[uid].receipt`, `accounts[uid].slotRetired`, `state.lastPublication`), 지갑 상태 파일 버전은 올리지 않는다(캐시는 메모리).

---

## 파일 구조

| 파일 | 책임 |
|---|---|
| `contracts/IMode3Roots.sol` (신규) | `revRoot()/regRoot()/epoch()/lastPublishedBlock()` 읽기 인터페이스 |
| `contracts/Mode3Log.sol` (V3 로 수정) | 캐노니컬: V3 다이제스트, 접수증 대기열, 강제·은퇴 |
| `contracts/Mode3Mirror.sol` (신규) | 거울: 세 해시 + 서명으로 root·epoch 갱신 |
| `contracts/Mode3Wallet.sol` (수정) | `Mode3Log log` → `IMode3Roots log` |
| `lib/mode3_log.js` (수정) | V3 다이제스트·서명, 접수증, 거울 ABI/해시, `MODE3_ROOTS_ABI` (V2 함수 삭제) |
| `lib/mode3_wallet.js` `syncRevocationTree` / `lib/mode3_registry_sync.js` (수정) | `{ untilEpoch, expectRoot }` 옵션 — 거울 epoch 시점의 트리 |
| `lib/mode3_rp.js` (수정) | `MODE3_ROOTS_ABI` 로 읽기(거울·로그 둘 다 됨) |
| `cia.js` (수정) | V3 게시, pending 강제 따르기, 접수증, 릴레이 루프, 건강 정보 |
| `lib/mode3_cia_state.js` (수정) | v10 이행 |
| `lib/mode3_health.js` (수정) | AA 건강에 `mirrors[]` |
| `mode3_rp.js` (수정) | `MODE3_MIRROR_ADDRESS` 로 검증기·팩토리 |
| `mode3_wallet_agent.js` (수정) | 두 provider, 거울 뷰, `syncAll` → `syncFor(mirror)`, 캐시 키 chainid |
| `tests/helpers/mode3_chain.mjs` / `isolated_cia.mjs` / `isolated_mode3_stack.mjs` (수정) | 거울 배포·env·`publishV3`·`relayToMirror` |
| `scripts/deploy_mode3_log.cjs` (수정) | 로그 + 거울 배포 |
| `scripts/run_tests.sh` (수정) | 새 테스트 등록 |
| `docs/MODE3_DEMO.md` (수정) | 런북 |

---

### Task 1: `IMode3Roots` + `Mode3Log` V3 다이제스트 + `Mode3Wallet` 인터페이스화 + JS V3 다이제스트

**Files:**
- Create: `contracts/IMode3Roots.sol`
- Modify: `contracts/Mode3Log.sol` (DOMAIN·digestFor), `contracts/Mode3Wallet.sol:5,19,61`
- Modify: `lib/mode3_log.js` (V2 → V3)
- Test: `test/Mode3Log.test.mjs`(digest·재생 케이스 갱신), `test/Mode3Wallet.test.mjs`(변경 없이 통과해야 함)

**Interfaces:**
- Produces (Solidity): `interface IMode3Roots { function revRoot() external view returns (bytes32); function regRoot() external view returns (bytes32); function epoch() external view returns (uint64); function lastPublishedBlock() external view returns (uint64); }`
- Produces (JS, `lib/mode3_log.js`): `DOMAIN_LOG_V3`, `MODE3_ROOTS_ABI`(4 getter), `MODE3_LOG_ABI`(V3), `entryHashes({ revLeaves, slotIdx, slotLeaves }) → { hLeaves, hIdx, hSlots }`, `publicationDigestV3({ canonicalChainId, canonicalLogAddress, revRoot, regRoot, epoch, revLeaves, slotIdx, slotLeaves })`, `publicationDigestV3Hashed({ canonicalChainId, canonicalLogAddress, revRoot, regRoot, epoch, hLeaves, hIdx, hSlots })`, `signPublicationV3(wallet, params)`. `publicationDigestV2`/`signPublicationV2`/`DOMAIN_LOG_V2` 는 삭제(사용처는 Task 4·5 가 옮긴다 — 그때까지 chain 그룹은 빨갛다. V1 `publicationDigest`/`signRootPublication` 은 Mode 2 용이라 남긴다).

- [ ] **Step 1: 실패하는 컨트랙트 테스트** — `test/Mode3Log.test.mjs` 의 `sign` 헬퍼와 digest 케이스를 V3 로 바꾼다.

```js
import { signPublicationV3, publicationDigestV3, rootToBytes32 } from '../lib/mode3_log.js';
// beforeEach 뒤
const canon = async () => ({ canonicalChainId: (await ethers.provider.getNetwork()).chainId, canonicalLogAddress: await log.getAddress() });
const sign = async (wallet, p) => signPublicationV3(wallet, { ...(await canon()), ...p });
// '다른 로그의 게시를 재생하면 거절' 케이스는 그대로 두되 서명은 sign(cia, p)
// digest 케이스:
it('digestFor 가 JS publicationDigestV3 와 같다 (chainid·주소를 덮는다)', async () => {
  const p = { revRoot: b32(9n), regRoot: b32(8n), epoch: 3n, revLeaves: [b32(7n)], slotIdx: [4], slotLeaves: [b32(44n)] };
  expect(await log.digestFor(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves)).to.equal(publicationDigestV3({ ...(await canon()), ...p }));
  expect(await log.DOMAIN()).to.equal(ethers.keccak256(ethers.toUtf8Bytes('MODE3_LOG_V3')));
});
```

- [ ] **Step 2: 실패 확인** — `npx hardhat test test/Mode3Log.test.mjs` → `publicationDigestV3 is not exported` 류로 실패.

- [ ] **Step 3: 구현**

`contracts/IMode3Roots.sol`:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
/// @title 검증자가 읽는 폐기 상태 — 캐노니컬 Mode3Log(폐기 체인)와 Mode3Mirror(응용 체인)가 같은 모양으로 낸다(V10 설계 §2).
interface IMode3Roots {
    function revRoot() external view returns (bytes32);
    function regRoot() external view returns (bytes32);
    function epoch() external view returns (uint64);
    function lastPublishedBlock() external view returns (uint64);
}
```

`contracts/Mode3Log.sol` 변경(헤더 주석을 V3 로, 상속·DOMAIN·digestFor):
```solidity
import "./IMode3Roots.sol";
contract Mode3Log is IMode3Roots {
    bytes32 public constant DOMAIN = keccak256("MODE3_LOG_V3");
    // … 기존 상태 변수 그대로 …
    /// @dev V3: address(this) 앞에 block.chainid — 같은 서명이 거울(Mode3Mirror)에서도 유효해야 하므로 거울은 이 둘을 생성자로 받아 같은 값을 넣는다.
    function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] calldata revLeaves, uint32[] calldata slotIdx, bytes32[] calldata slotLeaves)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(
            DOMAIN, block.chainid, address(this), newRev, newReg, newEpoch,
            keccak256(abi.encodePacked(revLeaves)), keccak256(abi.encodePacked(slotIdx)), keccak256(abi.encodePacked(slotLeaves))
        ));
    }
```

`contracts/Mode3Wallet.sol`: `import "./Mode3Log.sol";` → `import "./IMode3Roots.sol";`, `Mode3Log public immutable log;` → `IMode3Roots public immutable log;`, 생성자 `log = Mode3Log(_log);` → `log = IMode3Roots(_log);`. 헤더 주석에 "폐기 근거 = IMode3Roots(캐노니컬 로그 또는 거울)" 한 줄.

`lib/mode3_log.js`: V2 블록을 다음으로 교체.
```js
// ---- V3 (Mode3Log 캐노니컬 + Mode3Mirror, 2026-10-02 V10) ----
export const DOMAIN_LOG_V3 = ethers.keccak256(ethers.toUtf8Bytes('MODE3_LOG_V3'));
export const MODE3_ROOTS_ABI = [
  'function revRoot() view returns (bytes32)',
  'function regRoot() view returns (bytes32)',
  'function epoch() view returns (uint64)',
  'function lastPublishedBlock() view returns (uint64)',
];
export const MODE3_LOG_ABI = [
  ...MODE3_ROOTS_ABI,
  'function cia() view returns (address)',
  'function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] revLeaves, uint32[] slotIdx, bytes32[] slotLeaves) view returns (bytes32)',
  'function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] revLeaves, uint32[] slotIdx, bytes32[] slotLeaves, bytes sig)',
  'event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves)',
  'event SlotUpdated(uint64 indexed epoch, uint32 index, bytes32 leaf)',
];
const packedHash = (types, vals) => ethers.keccak256(vals.length ? ethers.solidityPacked(types, vals) : '0x');
/** 컨트랙트가 서명 안에서 쓰는 세 배열의 해시. slotIdx 는 32바이트 패딩 패킹(Solidity encodePacked(uint32[]) 규칙). */
export function entryHashes({ revLeaves, slotIdx, slotLeaves }) {
  if (slotIdx.length !== slotLeaves.length) throw new Error('entryHashes: slotIdx 와 slotLeaves 길이가 다르다');
  return { hLeaves: packedHash(revLeaves.map(() => 'bytes32'), revLeaves), hIdx: packedHash(slotIdx.map(() => 'uint256'), slotIdx), hSlots: packedHash(slotLeaves.map(() => 'bytes32'), slotLeaves) };
}
export function publicationDigestV3Hashed({ canonicalChainId, canonicalLogAddress, revRoot, regRoot, epoch, hLeaves, hIdx, hSlots }) {
  if (canonicalChainId === undefined || canonicalChainId === null || !canonicalLogAddress) throw new Error('publicationDigestV3: canonicalChainId·canonicalLogAddress 가 필요하다');
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'uint256', 'address', 'bytes32', 'bytes32', 'uint64', 'bytes32', 'bytes32', 'bytes32'],
    [DOMAIN_LOG_V3, BigInt(canonicalChainId), canonicalLogAddress, revRoot, regRoot, epoch, hLeaves, hIdx, hSlots]));
}
export function publicationDigestV3({ revLeaves, slotIdx, slotLeaves, ...rest }) {
  return publicationDigestV3Hashed({ ...rest, ...entryHashes({ revLeaves, slotIdx, slotLeaves }) });
}
export function signPublicationV3(wallet, params) { return wallet.signMessage(ethers.getBytes(publicationDigestV3(params))); }
```

- [ ] **Step 4: 통과 확인** — `npx hardhat test test/Mode3Log.test.mjs test/Mode3Wallet.test.mjs` → 전부 PASS(Mode3Wallet 은 Mode3Log 를 그대로 배포해 쓰므로 변경 없이 통과해야 한다; 안 되면 `IMode3Roots` 캐스팅을 확인).

- [ ] **Step 5: Commit** — `git add contracts/IMode3Roots.sol contracts/Mode3Log.sol contracts/Mode3Wallet.sol lib/mode3_log.js test/Mode3Log.test.mjs && git commit -m "feat(mode3): V10 1/N — IMode3Roots, Mode3Log V3 digest(chainid+address), JS V3 digest"`

---

### Task 2: `Mode3Log` 접수증 대기열 — `requestRevocation`, 게시 강제, 영구 은퇴

**Files:**
- Modify: `contracts/Mode3Log.sol`
- Modify: `lib/mode3_log.js` (접수증 다이제스트·서명·검증, ABI 추가)
- Test: `test/Mode3Log.test.mjs`

**Interfaces:**
- Solidity: `function requestRevocation(uint32 slot, uint64 epochAtRequest, uint64 requestedAt, bytes calldata sig) external` (이미 pending/retired 면 아무 일 없이 return), `function pendingSlots() external view returns (uint32[] memory)`, `function isRetired(uint32 slot) external view returns (bool)`, `event RevocationRequested(uint32 indexed slot, uint64 epochAtRequest)`, `event SlotRetired(uint32 indexed slot, uint64 epoch)`, `error PendingRevocationNotApplied(uint32 slot)`, `error SlotRetired(uint32 slot)`, `bytes32 public constant D_RECEIPT = keccak256("MODE3_REVOKE_RECEIPT_V1")`, `function receiptDigestFor(uint32 slot, uint64 epochAtRequest, uint64 requestedAt) public view returns (bytes32)`.
- JS: `DOMAIN_RECEIPT`, `receiptDigest({ canonicalChainId, canonicalLogAddress, slot, epochAtRequest, requestedAt })`, `signReceipt(wallet, params)`, `verifyReceipt(ciaAddress, params, sig) → boolean`(ethers.verifyMessage), `MODE3_LOG_ABI` 에 위 함수·이벤트 추가.

- [ ] **Step 1: 실패하는 테스트**

```js
import { signReceipt, receiptDigest } from '../lib/mode3_log.js';
const receipt = async (wallet, slot, epochAtRequest, requestedAt) => signReceipt(wallet, { ...(await canon()), slot, epochAtRequest, requestedAt });
it('접수증: CIA 서명만 받고 pendingSlots 에 적는다, 중복은 무해', async () => {
  const sig = await receipt(cia, 7, 0n, 1000n);
  await expect(log.connect(stranger).requestRevocation(7, 0n, 1000n, sig)).to.emit(log, 'RevocationRequested').withArgs(7, 0n);
  expect(await log.pendingSlots()).to.deep.equal([7n]);
  await log.requestRevocation(7, 0n, 1000n, sig);   // 두 번째는 no-op
  expect(await log.pendingSlots()).to.deep.equal([7n]);
  await expect(log.requestRevocation(8, 0n, 1000n, await receipt(stranger, 8, 0n, 1000n))).to.be.revertedWithCustomError(log, 'BadSignature');
  expect(await log.receiptDigestFor(7, 0n, 1000n)).to.equal(receiptDigest({ ...(await canon()), slot: 7, epochAtRequest: 0n, requestedAt: 1000n }));
});
it('강제: pending 슬롯이 0 으로 실리지 않은 publish 는 거절, 실리면 통과하고 슬롯은 은퇴', async () => {
  await log.requestRevocation(7, 0n, 1000n, await receipt(cia, 7, 0n, 1000n));
  const bad = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] };
  await expect(log.publish(bad.revRoot, bad.regRoot, 1n, [], [], [], await sign(cia, bad))).to.be.revertedWithCustomError(log, 'PendingRevocationNotApplied').withArgs(7);
  const bad2 = { ...bad, slotIdx: [7], slotLeaves: [b32(5n)] };   // 0 이 아닌 값으로는 안 된다
  await expect(log.publish(bad2.revRoot, bad2.regRoot, 1n, [], [7], [b32(5n)], await sign(cia, bad2))).to.be.revertedWithCustomError(log, 'PendingRevocationNotApplied').withArgs(7);
  const ok = { ...bad, slotIdx: [7], slotLeaves: [b32(0n)] };
  await expect(log.publish(ok.revRoot, ok.regRoot, 1n, [], [7], [b32(0n)], await sign(cia, ok))).to.emit(log, 'SlotRetired').withArgs(7, 1n);
  expect(await log.pendingSlots()).to.deep.equal([]);
  expect(await log.isRetired(7)).to.equal(true);
  const reuse = { ...bad, epoch: 2n, slotIdx: [7], slotLeaves: [b32(9n)] };
  await expect(log.publish(reuse.revRoot, reuse.regRoot, 2n, [], [7], [b32(9n)], await sign(cia, reuse))).to.be.revertedWithCustomError(log, 'SlotRetired').withArgs(7);
  const zeroAgain = { ...bad, epoch: 2n, slotIdx: [7], slotLeaves: [b32(0n)] };   // 0 으로 다시 쓰는 건 허용(멱등)
  await log.publish(zeroAgain.revRoot, zeroAgain.regRoot, 2n, [], [7], [b32(0n)], await sign(cia, zeroAgain));
});
it('은퇴된 슬롯에 대한 접수증은 no-op', async () => { /* 위 흐름 뒤 requestRevocation(7, …) 이 pendingSlots 를 비워 둔 채 통과 */ });
```

- [ ] **Step 2: 실패 확인** — `npx hardhat test test/Mode3Log.test.mjs` → `requestRevocation is not a function`.

- [ ] **Step 3: 구현** (`contracts/Mode3Log.sol` 에 추가)

```solidity
    bytes32 public constant D_RECEIPT = keccak256("MODE3_REVOKE_RECEIPT_V1");
    mapping(uint32 => bool) public pending;
    uint32[] private pendingList;
    mapping(uint32 => bool) public isRetired;

    event RevocationRequested(uint32 indexed slot, uint64 epochAtRequest);
    event SlotRetired(uint32 indexed slot, uint64 epoch);
    error PendingRevocationNotApplied(uint32 slot);
    error SlotRetired(uint32 slot);

    function pendingSlots() external view returns (uint32[] memory) { return pendingList; }

    function receiptDigestFor(uint32 slot, uint64 epochAtRequest, uint64 requestedAt) public view returns (bytes32) {
        return keccak256(abi.encode(D_RECEIPT, block.chainid, address(this), slot, epochAtRequest, requestedAt));
    }

    /// @notice 사용자(또는 누구든)가 IdP 가 서명한 폐기 접수증을 올린다(V10 §4). 다음 publish 는 이 슬롯을 0 으로 실어야 한다.
    function requestRevocation(uint32 slot, uint64 epochAtRequest, uint64 requestedAt, bytes calldata sig) external {
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", receiptDigestFor(slot, epochAtRequest, requestedAt)));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        if (pending[slot] || isRetired[slot]) return;
        pending[slot] = true;
        pendingList.push(slot);
        emit RevocationRequested(slot, epochAtRequest);
    }
```
`publish` 에서 서명 검증 **뒤**, 상태 갱신 **앞**에:
```solidity
        for (uint256 i = 0; i < slotIdx.length; i++) {
            if (isRetired[slotIdx[i]] && slotLeaves[i] != bytes32(0)) revert SlotRetired(slotIdx[i]);
        }
        uint256 n = pendingList.length;
        for (uint256 p = 0; p < n; p++) {
            uint32 s = pendingList[p];
            bool applied = false;
            for (uint256 i = 0; i < slotIdx.length; i++) {
                if (slotIdx[i] == s && slotLeaves[i] == bytes32(0)) { applied = true; break; }
            }
            if (!applied) revert PendingRevocationNotApplied(s);
            pending[s] = false;
            isRetired[s] = true;
            emit SlotRetired(s, newEpoch);
        }
        delete pendingList;
```
`lib/mode3_log.js`:
```js
export const DOMAIN_RECEIPT = ethers.keccak256(ethers.toUtf8Bytes('MODE3_REVOKE_RECEIPT_V1'));
export function receiptDigest({ canonicalChainId, canonicalLogAddress, slot, epochAtRequest, requestedAt }) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'uint256', 'address', 'uint32', 'uint64', 'uint64'],
    [DOMAIN_RECEIPT, BigInt(canonicalChainId), canonicalLogAddress, slot, epochAtRequest, requestedAt]));
}
export function signReceipt(wallet, params) { return wallet.signMessage(ethers.getBytes(receiptDigest(params))); }
export function verifyReceipt(ciaAddress, params, sig) {
  try { return ethers.verifyMessage(ethers.getBytes(receiptDigest(params)), sig).toLowerCase() === ciaAddress.toLowerCase(); } catch { return false; }
}
```
`MODE3_LOG_ABI` 에 `'function requestRevocation(uint32 slot, uint64 epochAtRequest, uint64 requestedAt, bytes sig)'`, `'function pendingSlots() view returns (uint32[])'`, `'function isRetired(uint32) view returns (bool)'`, `'function receiptDigestFor(uint32,uint64,uint64) view returns (bytes32)'`, `'event RevocationRequested(uint32 indexed slot, uint64 epochAtRequest)'`, `'event SlotRetired(uint32 indexed slot, uint64 epoch)'` 추가.

- [ ] **Step 4: 통과 확인** — `npx hardhat test test/Mode3Log.test.mjs`.
- [ ] **Step 5: Commit** — `git commit -m "feat(mode3): V10 2/N — Mode3Log 접수증 대기열·게시 강제·슬롯 영구 은퇴"`

---

### Task 3: `Mode3Mirror` 컨트랙트 + JS 거울 ABI + 거울 위의 `Mode3Wallet`

**Files:**
- Create: `contracts/Mode3Mirror.sol`
- Modify: `lib/mode3_log.js` (`MODE3_MIRROR_ABI`, `signPublicationV3Hashed`)
- Test: `test/Mode3Mirror.test.mjs` (신규), `test/Mode3Wallet.test.mjs` 에 거울 케이스 1개

**Interfaces:**
- Solidity `Mode3Mirror is IMode3Roots`: `constructor(address cia_, uint256 canonicalChainId_, address canonicalLog_, bytes32 emptyRevRoot, bytes32 emptyRegRoot)`, immutables `cia, canonicalChainId, canonicalLog`, `function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots) public view returns (bytes32)`(캐노니컬 digestFor 와 바이트 단위로 같다), `function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, bytes calldata sig) external`, `event Mirrored(uint64 indexed epoch, bytes32 revRoot, bytes32 regRoot)`, errors `EpochNotIncreasing`, `BadSignature`.
- JS: `MODE3_MIRROR_ABI = [...MODE3_ROOTS_ABI, 'function cia() view returns (address)', 'function canonicalChainId() view returns (uint256)', 'function canonicalLog() view returns (address)', 'function publish(bytes32,bytes32,uint64,bytes32,bytes32,bytes32,bytes sig)', 'event Mirrored(uint64 indexed epoch, bytes32 revRoot, bytes32 regRoot)']`.

- [ ] **Step 1: 실패하는 테스트** — `test/Mode3Mirror.test.mjs`

```js
import { expect } from 'chai';
import hre from 'hardhat';
import { createRevocationTree } from '../lib/mode3_revocation.js';
import { createRegistryTree } from '../lib/mode3_registry.js';
import { signPublicationV3, entryHashes, rootToBytes32 } from '../lib/mode3_log.js';
const { ethers } = hre;
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);
describe('Mode3Mirror', () => {
  let log, mirror, cia, relayer, stranger, emptyRev, emptyReg, canon;
  beforeEach(async () => {
    [, cia, relayer, stranger] = await ethers.getSigners();
    emptyRev = rootToBytes32((await createRevocationTree()).getRoot()); emptyReg = rootToBytes32((await createRegistryTree()).root());
    log = await (await ethers.getContractFactory('Mode3Log')).deploy(cia.address, emptyRev, emptyReg);
    canon = { canonicalChainId: (await ethers.provider.getNetwork()).chainId, canonicalLogAddress: await log.getAddress() };
    mirror = await (await ethers.getContractFactory('Mode3Mirror')).deploy(cia.address, canon.canonicalChainId, canon.canonicalLogAddress, emptyRev, emptyReg);
  });
  it('캐노니컬에 올린 서명을 그대로 거울에 올리면 같은 root·epoch 가 적힌다(제출자는 아무나)', async () => {
    const p = { revRoot: b32(9n), regRoot: b32(8n), epoch: 1n, revLeaves: [b32(1n)], slotIdx: [7], slotLeaves: [b32(70n)] };
    const sig = await signPublicationV3(cia, { ...canon, ...p });
    await log.publish(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves, sig);
    const h = entryHashes(p);
    await expect(mirror.connect(relayer).publish(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots, sig)).to.emit(mirror, 'Mirrored').withArgs(1n, p.revRoot, p.regRoot);
    expect(await mirror.revRoot()).to.equal(p.revRoot); expect(await mirror.regRoot()).to.equal(p.regRoot); expect(await mirror.epoch()).to.equal(1n);
    expect(await mirror.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
    expect(await mirror.digestFor(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots)).to.equal(await log.digestFor(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves));
  });
  it('epoch 미증가·남의 서명·다른 캐노니컬(주소)의 서명은 거절', async () => {
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [] };
    const h = entryHashes(p);
    await expect(mirror.publish(p.revRoot, p.regRoot, 0n, h.hLeaves, h.hIdx, h.hSlots, await signPublicationV3(cia, { ...canon, ...p, epoch: 0n }))).to.be.revertedWithCustomError(mirror, 'EpochNotIncreasing');
    await expect(mirror.publish(p.revRoot, p.regRoot, 1n, h.hLeaves, h.hIdx, h.hSlots, await signPublicationV3(stranger, { ...canon, ...p }))).to.be.revertedWithCustomError(mirror, 'BadSignature');
    await expect(mirror.publish(p.revRoot, p.regRoot, 1n, h.hLeaves, h.hIdx, h.hSlots, await signPublicationV3(cia, { ...canon, canonicalLogAddress: stranger.address, ...p }))).to.be.revertedWithCustomError(mirror, 'BadSignature');
  });
  it('건너뛴 epoch 도 받는다(거울은 뒤처질 수 있다)', async () => {
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 5n, revLeaves: [], slotIdx: [], slotLeaves: [] };
    const h = entryHashes(p);
    await mirror.publish(p.revRoot, p.regRoot, 5n, h.hLeaves, h.hIdx, h.hSlots, await signPublicationV3(cia, { ...canon, ...p }));
    expect(await mirror.epoch()).to.equal(5n);
  });
});
```
`test/Mode3Wallet.test.mjs` 에 케이스 1개 추가(기존 fixture 가 로그를 배포하는 자리 뒤에): 거울을 배포해 그 주소로 지갑을 만들고, 거울 root 와 같은 π 는 통과·거울이 뒤처져 있으면(캐노니컬만 새 epoch) 캐노니컬 root 의 π 가 `StaleRevocationRoot` 로 거절되는지. 기존 테스트가 쓰는 π 생성 헬퍼를 그대로 쓰되 `logAddress` 를 거울 주소로 넘긴다.

- [ ] **Step 2: 실패 확인** — `npx hardhat test test/Mode3Mirror.test.mjs` → `Mode3Mirror` 아티팩트 없음.

- [ ] **Step 3: 구현** — `contracts/Mode3Mirror.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "./IMode3Roots.sol";
/// @title Mode 3 거울(V10 설계 §2·§3·§5) — 응용 체인에서 폐기 체인의 캐노니컬 Mode3Log 의 (revRoot, regRoot, epoch) 를 받아 적는다.
/// @notice 신뢰 근거는 IdP 서명뿐이다(결정 1-A). 다이제스트는 캐노니컬 Mode3Log.digestFor 와 바이트 단위로 같다 — 리프·슬롯 배열 대신
///   그 세 해시를 받으므로 같은 서명이 양쪽에 유효하다. 이 체인의 검증자(Mode3Wallet, RP)는 이 값만 본다.
contract Mode3Mirror is IMode3Roots {
    bytes32 public constant DOMAIN = keccak256("MODE3_LOG_V3");
    address public immutable cia;
    uint256 public immutable canonicalChainId;
    address public immutable canonicalLog;
    bytes32 public revRoot;
    bytes32 public regRoot;
    uint64 public epoch;
    uint64 public lastPublishedBlock;
    event Mirrored(uint64 indexed epoch, bytes32 revRoot, bytes32 regRoot);
    error EpochNotIncreasing(uint64 got, uint64 have);
    error BadSignature();
    constructor(address cia_, uint256 canonicalChainId_, address canonicalLog_, bytes32 emptyRevRoot, bytes32 emptyRegRoot) {
        cia = cia_; canonicalChainId = canonicalChainId_; canonicalLog = canonicalLog_;
        revRoot = emptyRevRoot; regRoot = emptyRegRoot; lastPublishedBlock = uint64(block.number);
    }
    function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, canonicalChainId, canonicalLog, newRev, newReg, newEpoch, hLeaves, hIdx, hSlots));
    }
    function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, bytes calldata sig) external {
        if (newEpoch <= epoch) revert EpochNotIncreasing(newEpoch, epoch);
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digestFor(newRev, newReg, newEpoch, hLeaves, hIdx, hSlots)));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        revRoot = newRev; regRoot = newReg; epoch = newEpoch; lastPublishedBlock = uint64(block.number);
        emit Mirrored(newEpoch, newRev, newReg);
    }
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) { /* Mode3Log._recover 와 같은 본문(low-s, v∈{27,28}) */ }
}
```
`lib/mode3_log.js` 에 `MODE3_MIRROR_ABI` 추가.

- [ ] **Step 4: 통과 확인** — `npx hardhat test test/Mode3Mirror.test.mjs test/Mode3Wallet.test.mjs test/Mode3Log.test.mjs`.
- [ ] **Step 5: Commit** — `git commit -m "feat(mode3): V10 3/N — Mode3Mirror(응용 체인 거울) + 거울 위 Mode3Wallet 검사"`

---

### Task 4: chain 그룹 헬퍼와 기존 테스트를 V3 로 이행(거울은 아직 미사용)

**Files:**
- Modify: `tests/helpers/mode3_chain.mjs` (`deployMode3Log` 는 V3 아티팩트 그대로, `deployMode3Mirror`, `publishV3`, `relayToMirror` 추가, `publishV2` 삭제)
- Modify: `tests/helpers/isolated_cia.mjs` (거울도 배포, `cia.mirrorAddress`, env `CIA_MIRRORS`, `CIA_MIRROR_HEARTBEAT_BLOCKS: '0'`)
- Modify: 사용처 — `tests/test_mode3_rcl_sync.mjs`, `tests/test_mode3_wallet.mjs`, `tests/test_cia_registry.mjs`, `tests/test_cia_startup.mjs`, `tests/test_mode3_e2e.mjs`, `scripts/bench_mode3_onchain.mjs`(`publishV2`/`signPublicationV2`/`publicationDigestV2` → V3 이름; 서명 인자에 `canonicalChainId`·`canonicalLogAddress`)

**Interfaces:**
- `deployMode3Mirror(ciaAddress, canonicalLogAddress, provider = getProvider()) → { address, contract }`(`canonicalChainId` 는 `(await provider.getNetwork()).chainId`)
- `publishV3(log, ciaWallet, { revRoot, regRoot, epoch, revLeaves = [], slotIdx = [], slotLeaves = [] }) → { sig, p }`(bigint 인자, 캐노니컬에 올리고 서명·바이트 파라미터를 돌려준다)
- `relayToMirror(mirror, signer, { p, sig })`(`entryHashes(p)` 로 세 해시를 만들어 `mirror.publish`)
- `canonOf(log, provider) → { canonicalChainId, canonicalLogAddress }`

- [ ] **Step 1: 실패 확인(현재 상태)** — `node tests/test_mode3_rcl_sync.mjs` → `publishV2 is not exported` 로 실패(Task 1 에서 V2 삭제).
- [ ] **Step 2: 헬퍼 구현**

```js
const ARTIFACT_MIRROR = path.join(ROOT_DIR, 'artifacts', 'contracts', 'Mode3Mirror.sol', 'Mode3Mirror.json');
function artifactMirror() { if (!fs.existsSync(ARTIFACT_MIRROR)) execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' }); return JSON.parse(fs.readFileSync(ARTIFACT_MIRROR, 'utf8')); }
export async function canonOf(log, provider = getProvider()) { return { canonicalChainId: (await provider.getNetwork()).chainId, canonicalLogAddress: await log.getAddress() }; }
export async function deployMode3Mirror(ciaAddress, canonicalLogAddress, provider = getProvider()) {
  const { abi, bytecode } = artifactMirror();
  const emptyRev = rootToBytes32((await createRevocationTree()).getRoot()); const emptyReg = rootToBytes32((await createRegistryTree()).root());
  const factory = new ethers.ContractFactory(abi, bytecode, await getFunder(provider));
  const contract = await factory.deploy(ciaAddress, (await provider.getNetwork()).chainId, canonicalLogAddress, emptyRev, emptyReg);
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), contract };
}
export async function publishV3(log, ciaWallet, { revRoot, regRoot, epoch, revLeaves = [], slotIdx = [], slotLeaves = [] }) {
  const b = rootToBytes32;
  const p = { revRoot: b(revRoot), regRoot: b(regRoot), epoch, revLeaves: revLeaves.map(b), slotIdx, slotLeaves: slotLeaves.map(b) };
  const sig = await signPublicationV3(ciaWallet, { ...(await canonOf(log, ciaWallet.provider)), ...p });
  await (await log.connect(ciaWallet).publish(p.revRoot, p.regRoot, epoch, p.revLeaves, slotIdx, p.slotLeaves, sig)).wait();
  return { sig, p };
}
export async function relayToMirror(mirror, signer, { p, sig }) {
  const h = entryHashes(p);
  await (await mirror.connect(signer).publish(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots, sig)).wait();
}
```
`isolated_cia.mjs`: `const { address: logAddress } = await deployMode3Log(...)` 뒤에 `const { address: mirrorAddress } = await deployMode3Mirror(ethWallet.address, logAddress, provider);` env 에 `CIA_MIRRORS: \`31337=${mirrorAddress}\``, `CIA_CHAIN_RPCS: '31337=' + RPC` (지금 빈 문자열인 것을 명시 값으로), `CIA_MIRROR_HEARTBEAT_BLOCKS: '0'`; 반환 객체에 `mirrorAddress` 와 `mirrorContract`(provider 연결) 추가. CIA 가 아직 이 env 를 모르는 동안은 무시된다(Task 6 에서 읽는다).

- [ ] **Step 3: 사용처 이행** — 위 파일들의 `publishV2(` → `publishV3(`, `signPublicationV2(wallet, { logAddress, ...p })` → `signPublicationV3(wallet, { ...(await canonOf(log, provider)), ...p })`, `publicationDigestV2` → `publicationDigestV3`. `tests/test_cia_registry.mjs` 의 "CIA 몰래 직접 게시" 크래시 복구 케이스도 같은 치환.
- [ ] **Step 4: 통과 확인** — `npx hardhat node` 가 :8545 에 떠 있는 상태에서 `node tests/test_mode3_rcl_sync.mjs && node tests/test_mode3_wallet.mjs` → PASS. `cia.js` 는 아직 V2 서명을 쓰므로 `test_cia_*`·e2e 는 **Task 5 까지 빨갛다**(원장에 기록).
- [ ] **Step 5: Commit** — `git commit -m "test(mode3): V10 4/N — chain 헬퍼 V3(publishV3·거울 배포·relayToMirror), 사용처 이행"`

---

### Task 5: CIA 게시 V3 + 대기열 따르기 + 접수증 + 상태 v10

**Files:**
- Modify: `cia.js` (`publishNow`, `revokeAccount`, `/cia/revoke`, `/cia/account/self_revoke`, `assignSlot`/재발급 경로, `/cia/public_keys`)
- Modify: `lib/mode3_cia_state.js` (v10)
- Test: `tests/test_mode3_cia_state.js`(v9→v10 이행 1건), `tests/test_cia_registry.mjs`(접수증·대기열 강제 2건)

**Interfaces:**
- 응답: `revokeAccount(uid)` 와 `/cia/revoke scope=account|credential` 의 JSON 에 `receipt: { slot, epochAtRequest, requestedAt, sig, canonicalChainId, canonicalLogAddress }` (은퇴할 활성 자격증명이 없어 `retired:false` 여도 접수증은 낸다 — "이 슬롯은 비어 있어야 한다" 는 약속). `accounts[uid].receipt` 에 마지막 접수증 저장(멱등 재요청은 같은 것을 돌려준다).
- `publishNow` 는 게시 전에 `log.pendingSlots()` 를 읽어, 각 pending 슬롯에 대해 (a) 그 슬롯의 계정을 찾아 `acct.disabled = true`, 활성 자격증명 은퇴, `setSlot(uid, 0n)`(이미 0 이면 멱등), `acct.slotRetired = true`, (b) 이번 `slotIdx/slotLeaves` 에 `(slot, 0)` 이 없으면 추가한다. 게시 성공 뒤 `state.lastPublication = { revRoot, regRoot, epoch, hLeaves, hIdx, hSlots, sig, txHash }` 저장(Task 6 의 릴레이가 쓴다).
- `slotRetired` 인 계정의 재발급(`/cia/user_cred`)·재등록은 **새 슬롯**을 배정한다: `acct.slot = state.registry.next++; acct.slotRetired = false` 를 발급 직전에 수행(계정이 disabled 면 기존대로 거절 — 관리자가 되살린 뒤의 발급이 새 슬롯을 받는다).
- `GET /cia/public_keys` 에 `canonicalChainId`, `mirrors: [{ chainId, address }]`(Task 6 전에는 `[]`) 추가.
- 상태 v10 이행: `accounts[*].receipt ??= null; accounts[*].slotRetired ??= false; state.lastPublication ??= null; version = 10`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_cia_registry.mjs` 에 추가(기존 `cia`·`provider`·`log` 픽스처 사용):

```js
await t('자기 폐기 응답에 IdP 서명 접수증이 실리고, 접수증은 캐노니컬 로그가 받아들인다', async () => {
  const r = await post(`${cia.base}/cia/account/self_revoke`, { uid, pwd });
  assert.equal(r.status, 200);
  const rc = r.body.receipt;
  assert.ok(rc && typeof rc.sig === 'string' && rc.slot === slotOf(uid));
  assert.equal(verifyReceipt(cia.ethAddress, rc, rc.sig), true);
  const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, await provider.getSigner(0));
  // 이미 즉시 게시로 0 이 됐어도 접수증 제출은 유효하고, 다음 게시(하트비트)가 (slot, 0) 을 실어 통과한다
  await (await log.requestRevocation(rc.slot, rc.epochAtRequest, rc.requestedAt, rc.sig)).wait();
  assert.deepEqual((await log.pendingSlots()).map(Number), [rc.slot]);
  const pub = await post(`${cia.base}/cia/publish`, {}, { 'X-CIA-Admin-Secret': cia.adminSecret });   // heartbeat 가 꺼져 있어 수동 게시
  assert.equal(pub.status, 200);
  assert.deepEqual(await log.pendingSlots(), []);
  assert.equal(await log.isRetired(rc.slot), true);
});
await t('은퇴된 슬롯의 계정을 되살려 재발급하면 새 슬롯을 받는다', async () => {
  await post(`${cia.base}/cia/account/set_disabled`, { uid, disabled: false }, { 'X-CIA-Admin-Secret': cia.adminSecret });
  const before = slotOf(uid);
  await issueUserCred(uid);   // 기존 헬퍼: /cia/user_cred 로 C_u 발급
  const after = (await get(`${cia.base}/cia/accounts`, { 'X-CIA-Admin-Secret': cia.adminSecret })).body.accounts.find((a) => a.uid === uid).slot;
  assert.notEqual(after, before);
});
```
`tests/test_mode3_cia_state.js` 에 "v9 파일을 읽으면 version 10, receipt=null, slotRetired=false, lastPublication=null" 1건.

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_cia_state.js`(unit) → FAIL; `node tests/test_cia_registry.mjs`(chain) → CIA 가 `signPublicationV2` import 로 기동 실패.

- [ ] **Step 3: 구현** (`cia.js`)

```js
import { MODE3_LOG_ABI, rootToBytes32, signPublicationV3, entryHashes, signReceipt, publicationDigestV3Hashed } from './lib/mode3_log.js';
let canonical = null;   // { canonicalChainId, canonicalLogAddress } — 기동 때 provider.getNetwork() 로 한 번
async function canonicalParams() { return (canonical ??= { canonicalChainId: (await ethWallet.provider.getNetwork()).chainId, canonicalLogAddress: LOG_ADDRESS }); }
async function makeReceipt(slot) {
  const params = { ...(await canonicalParams()), slot, epochAtRequest: BigInt(state.epoch), requestedAt: BigInt(Math.floor(Date.now() / 1000)) };
  const sig = await signReceipt(ethWallet, params);
  return { slot, epochAtRequest: params.epochAtRequest.toString(), requestedAt: params.requestedAt.toString(), sig, canonicalChainId: params.canonicalChainId.toString(), canonicalLogAddress: LOG_ADDRESS };
}
```
`revokeAccount`: `const receipt = acct.receipt ?? (acct.receipt = await makeReceipt(acct.slot)); persist();` 를 `persist()` 앞에 넣고 반환 객체에 `receipt`. `/cia/revoke scope=credential` 도 같은 방식(`acct.receipt` 갱신).
`publishNow` 안, `const slots = …` 직전:
```js
    const pendingOnChain = (await log.pendingSlots()).map(Number);
    for (const slot of pendingOnChain) {
      const entry = Object.entries(state.accounts).find(([, a]) => a.slot === slot);
      if (entry) { const [uid, a] = entry; a.disabled = true; retireActiveCred(uid); setSlot(uid, 0n); a.slotRetired = true; }
      if (!state.registry.pendingSlots.some((s) => s.index === slot && BigInt(s.leaf) === 0n)) state.registry.pendingSlots.push({ index: slot, leaf: '0' });
    }
```
서명: `const sig = await signPublicationV3(ethWallet, { ...(await canonicalParams()), revRoot, regRoot, epoch, revLeaves: leaves, slotIdx, slotLeaves });` 게시 뒤 `state.lastPublication = { revRoot, regRoot, epoch, ...entryHashes({ revLeaves: leaves, slotIdx, slotLeaves }), sig, txHash: tx.hash };`.
`setSlot` 이 `pendingSlots` 에 넣는 형식(`{index, leaf}`)은 기존 것을 그대로 쓴다 — `lib/mode3_registry.js`/`cia.js` 의 현행 `setSlot` 을 읽고 맞춘다.
새 슬롯 배정: `/cia/user_cred` 에서 `assignSlot`/`acct.slot` 을 쓰는 자리에 `if (acct.slotRetired) { acct.slot = state.registry.next++; acct.slotRetired = false; }`.
`lib/mode3_cia_state.js`: `CIA_STATE_VERSION = 10`, `if (state.version === 9) { for (const a of Object.values(state.accounts)) { a.receipt ??= null; a.slotRetired ??= false; } state.lastPublication ??= null; state.version = 10; notes.push('v9→v10: receipt·slotRetired·lastPublication'); }`, `defaultCiaState` 에 `lastPublication: null`.

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_cia_state.js`, 그 뒤 :8545 에서 `node tests/test_cia_registry.mjs && node tests/test_cia_startup.mjs && node tests/test_cia_register_issue.mjs && node tests/test_mode3_e2e.mjs` → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(cia): V10 5/N — V3 게시, 대기열 따르기(pending→0·은퇴), 폐기 접수증, 상태 v10"`

---

### Task 6: CIA 거울 릴레이 루프 + 건강 정보

**Files:**
- Modify: `cia.js` (env 파싱, `relayTick`, `heartbeatTick` 연계, `/cia/health`, `/cia/public_keys`)
- Modify: `lib/mode3_health.js` (`buildAaHealth` 에 `mirrors`)
- Test: `tests/test_cia_mirror_relay.mjs` (신규, chain), `tests/test_mode3_health_shape.js`(unit, `mirrors` 필드)

**Interfaces:**
- env: `CIA_MIRRORS="chainid=address[,…]"`, 각 chainid 의 RPC 는 `CIA_CHAIN_RPCS` 에 있어야 한다(없으면 기동 실패 메시지 `CIA_MIRRORS 의 chainid 31337 에 대한 RPC 가 CIA_CHAIN_RPCS 에 없다`). `CIA_MIRROR_HEARTBEAT_BLOCKS`(기본 50, 0 = 끔), `CIA_MIRROR_POLL_MS`(기본 5000).
- `relayTick()`: 거울마다 `[headX, mEpoch, mLast] = [provider_X.getBlockNumber(), mirror.epoch(), mirror.lastPublishedBlock()]`; `headX − mLast < H_X` 면 건너뜀; 아니면 `state.lastPublication` 이 없거나 `epoch ≤ mEpoch` 면 먼저 `await publishNow({ heartbeat: true })`(캐노니컬에 새 epoch 를 만든다 — 결정 3 의 "거울이 늙기 전에 캐노니컬에 올릴 새 epoch 가 있어야 한다"); 그 뒤 `mirror.publish(lastPublication.revRoot, …, sig)` 를 `ethWallet.connect(provider_X)` 로 보낸다. `EpochNotIncreasing` revert 는 "이미 갱신됨" 으로 무시.
- `POST /cia/admin/relay`(requireAdmin): 모든 거울을 즉시 갱신(하트비트 주기 무시) — 테스트·데모용. 응답 `{ mirrors: [{ chainId, epoch, txHash|null, skipped }] }`.
- 건강: `mirrors: [{ chainId, address, epoch, lastPublishedBlock, rootAge, behind: canonicalEpoch - epoch }]`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_cia_mirror_relay.mjs`

```js
// 격리 CIA + :8545 의 캐노니컬 로그·거울. 릴레이가 하트비트 주기로만 거울을 갱신하는지, 수동 relay 가 즉시 갱신하는지. (chain 그룹)
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, mineBlocks } from './helpers/mode3_chain.mjs';
import { MODE3_MIRROR_ABI, MODE3_LOG_ABI } from '../lib/mode3_log.js';
const provider = getProvider();
const cia = await startIsolatedCia({ env: { CIA_MIRROR_HEARTBEAT_BLOCKS: '5', CIA_MIRROR_POLL_MS: '300', CIA_HEARTBEAT_BLOCKS: '0' } });
const mirror = new ethers.Contract(cia.mirrorAddress, MODE3_MIRROR_ABI, provider);
const log = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
try {
  await t('계정 폐기 직후: 캐노니컬 epoch 는 올랐지만 거울은 아직 0 (하트비트 주기 전)', async () => {
    await registerAndIssue(cia, uid);                       // 기존 e2e 헬퍼 패턴(등록 → user_cred) — 즉시 게시로 캐노니컬 epoch ≥ 1
    assert.ok((await log.epoch()) >= 1n); assert.equal(await mirror.epoch(), 0n);
  });
  await t('주기만큼 블록이 지나면 릴레이가 거울을 캐노니컬 epoch 로 올린다', async () => {
    await mineBlocks(6);
    await waitFor(async () => (await mirror.epoch()) === (await log.epoch()), 5000);
    assert.equal(await mirror.revRoot(), await log.revRoot()); assert.equal(await mirror.regRoot(), await log.regRoot());
  });
  await t('캐노니컬에 새 epoch 가 없어도 주기가 지나면 캐노니컬 하트비트를 먼저 올리고 거울을 갱신한다', async () => {
    const e0 = await mirror.epoch(); await mineBlocks(6);
    await waitFor(async () => (await mirror.epoch()) > e0, 5000);
    assert.equal(await mirror.epoch(), await log.epoch());
  });
  await t('POST /cia/admin/relay 는 주기와 무관하게 즉시 갱신하고 /cia/health 가 mirrors 를 낸다', async () => {
    await post(`${cia.base}/cia/account/self_revoke`, { uid, pwd });
    const r = await post(`${cia.base}/cia/admin/relay`, {}, { 'X-CIA-Admin-Secret': cia.adminSecret });
    assert.equal(r.status, 200); assert.equal(await mirror.epoch(), await log.epoch());
    const h = (await get(`${cia.base}/cia/health`)).body;
    assert.equal(h.mirrors.length, 1); assert.equal(h.mirrors[0].behind, 0);
  });
} finally { await cia.stop(); }
```
- [ ] **Step 2: 실패 확인** — `node tests/test_cia_mirror_relay.mjs` → `cia.mirrorAddress` 는 있으나 거울 epoch 가 영원히 0 → waitFor 타임아웃 FAIL.
- [ ] **Step 3: 구현** — `cia.js`

```js
const MIRROR_HEARTBEAT_BLOCKS = envBig('CIA_MIRROR_HEARTBEAT_BLOCKS', 50);
const MIRROR_POLL_MS = Number(process.env.CIA_MIRROR_POLL_MS) || 5000;
const MIRRORS = [];   // [{ chainId: bigint, address, provider, contract }]
for (const item of (process.env.CIA_MIRRORS || '').split(',').map((s) => s.trim()).filter(Boolean)) {
  const i = item.indexOf('='); if (i <= 0) throw new Error(`CIA_MIRRORS 항목 "${item}" 은 chainid=address 형식이어야 한다`);
  const chainId = BigInt(item.slice(0, i)), address = ethers.getAddress(item.slice(i + 1));
  const rpc = CHAIN_RPCS.get(chainId.toString());
  if (!rpc) throw new Error(`CIA_MIRRORS 의 chainid ${chainId} 에 대한 RPC 가 CIA_CHAIN_RPCS 에 없다`);
  const provider = new ethers.JsonRpcProvider(rpc, undefined, { cacheTimeout: -1 });
  MIRRORS.push({ chainId, address, provider, contract: new ethers.Contract(address, MODE3_MIRROR_ABI, ethWallet.connect(provider)) });
}
let relaying = null;
async function relayMirror(m, { force = false } = {}) {
  const [head, mEpoch, mLast] = await Promise.all([m.provider.getBlockNumber(), m.contract.epoch(), m.contract.lastPublishedBlock()]);
  if (!force && BigInt(head) - BigInt(mLast) < MIRROR_HEARTBEAT_BLOCKS) return { chainId: m.chainId.toString(), epoch: mEpoch.toString(), txHash: null, skipped: true };
  if (!state.lastPublication || BigInt(state.lastPublication.epoch) <= BigInt(mEpoch)) {
    if (publishing) { try { await publishing; } catch { /* 경고는 그쪽 */ } }
    await publishNow({ heartbeat: true });   // 거울에 올릴 새 epoch 를 캐노니컬에 만든다
  }
  const lp = state.lastPublication;
  try {
    const tx = await m.contract.publish(lp.revRoot, lp.regRoot, lp.epoch, lp.hLeaves, lp.hIdx, lp.hSlots, lp.sig);
    await tx.wait();
    return { chainId: m.chainId.toString(), epoch: String(lp.epoch), txHash: tx.hash, skipped: false };
  } catch (e) {
    if (/EpochNotIncreasing/.test(e.message ?? '')) return { chainId: m.chainId.toString(), epoch: String(lp.epoch), txHash: null, skipped: true };   // 누군가 먼저 올렸다
    throw e;
  }
}
async function relayTick() {
  if (!LOG_ADDRESS || MIRRORS.length === 0 || MIRROR_HEARTBEAT_BLOCKS === 0n) return;
  if (relaying) return;
  relaying = (async () => { for (const m of MIRRORS) { try { await relayMirror(m); } catch (e) { console.warn(`[cia] 거울 ${m.chainId} 릴레이 실패: ${e.message}`); } } })();
  try { await relaying; } finally { relaying = null; }
}
if (MIRRORS.length && MIRROR_HEARTBEAT_BLOCKS > 0n) setInterval(relayTick, MIRROR_POLL_MS).unref();
app.post('/cia/admin/relay', requireAdmin, async (req, res) => {
  try { const out = []; for (const m of MIRRORS) out.push(await relayMirror(m, { force: true })); res.json({ mirrors: out }); }
  catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
```
`publishNow` 의 `state.lastPublication.epoch` 는 문자열로 저장(JSON). 건강(`/cia/health`): 거울마다 `{ chainId, address, epoch, lastPublishedBlock, rootAge: head - last, behind: state.epoch - epoch }` 를 `bounded(…, 1200)` 로 읽어 `mirrors` 로 넘기고 `buildAaHealth` 가 그대로 낸다(없으면 `[]`). `/cia/public_keys` 에 `canonicalChainId`, `mirrors: MIRRORS.map(({chainId, address}) => ({ chainId: chainId.toString(), address }))`.

- [ ] **Step 4: 통과 확인** — `node tests/test_cia_mirror_relay.mjs`, `node tests/test_mode3_health_shape.js`, 그리고 Task 5 의 chain 테스트 재실행(릴레이가 꺼진 격리 CIA 에서 회귀 없음).
- [ ] **Step 5: Commit** — `git commit -m "feat(cia): V10 6/N — 거울 릴레이 루프(하트비트 주기), /cia/admin/relay, 건강 mirrors"`

---

### Task 7: 동기화 라이브러리 — 거울 epoch 시점의 트리(`untilEpoch`, `expectRoot`)

**Files:**
- Modify: `lib/mode3_wallet.js` (`syncRevocationTree(provider, logAddress, opts = {})`), `lib/mode3_registry_sync.js` (`syncRegistryTree(provider, logAddress, opts = {})`), `lib/mode3_rcl_sync.js` (`syncAt({ untilEpoch, expectRoot })`)
- Test: `tests/test_mode3_rcl_sync.mjs`(2건), `tests/test_mode3_v9_lib.js` 또는 `tests/test_mode3_wallet.mjs`(등록부 1건)

**Interfaces:**
- `syncRevocationTree(provider, logAddress, { untilEpoch = null, expectRoot = null } = {})`: `untilEpoch` 가 있으면 `Revoked` 이벤트 중 `args.epoch <= untilEpoch` 만 순서대로 삽입하고, `expectRoot`(bigint) 와 다르면 throw `Error('폐기 트리 재생 root(…) 가 거울 revRoot(…) 와 다르다 — epoch E 까지')`; 없으면 현행(컨트랙트 최신 root 와 대조). 반환 `{ tree, root, head, epoch }`.
- `syncRegistryTree(provider, logAddress, { untilEpoch = null, expectRoot = null } = {})`: 같은 규칙(`SlotUpdated` 의 `args.epoch`).
- `createRevocationSync(...).syncAt({ untilEpoch, expectRoot })`: 체크포인트를 쓰지 않고 `syncRevocationTree(provider, logAddress, { untilEpoch, expectRoot })` 를 호출한 결과를 돌려준다(캐시는 손대지 않는다). `sync()` 는 현행 유지.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_rcl_sync.mjs` 끝에

```js
await t('untilEpoch: 캐노니컬이 두 번 더 게시돼도 epoch E 시점의 root 를 재구성한다', async () => {
  const e1 = await log.epoch(); const rootAtE1 = BigInt(await log.revRoot());
  await publish([111n]); await publish([222n]);
  const r = await syncRevocationTree(provider, logAddress, { untilEpoch: e1, expectRoot: rootAtE1 });
  assert.equal(r.root, rootAtE1); assert.equal(r.epoch, e1);
  await assert.rejects(syncRevocationTree(provider, logAddress, { untilEpoch: e1, expectRoot: 12345n }), /거울 revRoot/);
});
await t('createRevocationSync.syncAt 은 캐시를 건드리지 않는다', async () => {
  const rcl = createRevocationSync({ provider, logAddress, cacheFile, log: warn });
  await rcl.sync(); const before = fs.readFileSync(cacheFile, 'utf8');
  const e1 = (await log.epoch()) - 1n;
  await rcl.syncAt({ untilEpoch: e1, expectRoot: null });
  assert.equal(fs.readFileSync(cacheFile, 'utf8'), before);
});
```
등록부: 기존 등록부 동기화 테스트 파일에 "슬롯을 두 번 바꾼 뒤 첫 게시 epoch 로 `syncRegistryTree(..., { untilEpoch, expectRoot })` 하면 첫 값의 root" 1건.

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_rcl_sync.mjs` → `untilEpoch` 무시돼 root 불일치 FAIL.
- [ ] **Step 3: 구현** — `syncRevocationTree` 본문(현행 전체 재생 코드)에서 이벤트 루프를 `for (const e of events) { if (untilEpoch !== null && BigInt(e.args.epoch) > BigInt(untilEpoch)) continue; for (const l of e.args.leaves) await tree.insert(BigInt(l)); }` 로, 대조는 `const want = untilEpoch === null ? BigInt(onchainRoot) : expectRoot; if (want !== null && root !== want) throw …`, 반환 epoch 는 `untilEpoch ?? onchainEpoch`. `syncRegistryTree` 도 같은 꼴. `createRevocationSync` 에 `syncAt(opts) { return syncRevocationTree(provider, logAddress, opts); }`.
- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_rcl_sync.mjs && node tests/test_mode3_wallet.mjs`.
- [ ] **Step 5: Commit** — `git commit -m "feat(mode3): V10 7/N — 동기화에 untilEpoch·expectRoot(거울 epoch 시점의 트리)"`

---

### Task 8: RP — 자기 체인 거울만 읽는다

**Files:**
- Modify: `lib/mode3_rp.js` (ABI → `MODE3_ROOTS_ABI`, 주석)
- Modify: `mode3_rp.js` (`MODE3_MIRROR_ADDRESS` 필수, 팩토리 `logAddress: MIRROR_ADDRESS`, `/rp/info` 에 `mirrorAddress`, `logAddress` 는 캐노니컬 표시용으로 유지)
- Modify: `tests/helpers/isolated_mode3_stack.mjs` (RP env `MODE3_MIRROR_ADDRESS: cia.mirrorAddress`)
- Test: `tests/test_mode3_rp.mjs` (거울 지연 케이스 2건)

**Interfaces:**
- `createRpVerifier({ provider, logAddress, … })`: 인자 이름은 그대로(호출처 호환), 내부 ABI 만 `MODE3_ROOTS_ABI`. 거울이든 캐노니컬이든 같은 getter.
- `mode3_rp.js`: `const MIRROR_ADDRESS = process.env.MODE3_MIRROR_ADDRESS || null; if (!MIRROR_ADDRESS) { console.error('[rp] MODE3_MIRROR_ADDRESS 가 없다 — 이 체인의 Mode3Mirror 주소(V10)'); process.exit(1); }`; `createRpVerifier({ provider, logAddress: MIRROR_ADDRESS, … })`; `deployFactory(…, { logAddress: MIRROR_ADDRESS })`; `/rp/info` 에 `mirrorAddress: MIRROR_ADDRESS`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_rp.mjs` 에(기존 fixture: 격리 CIA, 로그인 π 생성 헬퍼):

```js
await t('거울이 뒤처지면 캐노니컬 root 의 π 는 stale_root, 거울 root 의 π 는 통과', async () => {
  const rpOnMirror = createRpVerifier({ provider, logAddress: cia.mirrorAddress, vkey, pkCIA: pk_CIA, arid, chainId: 31337n, pkTrace: pk_trace });
  await revokeSomeoneElsesSession();          // 캐노니컬 epoch +1 (즉시 게시), 거울은 그대로(릴레이 꺼짐)
  const piCanon = await loginProofAgainst(cia.logAddress);   // 기존 헬퍼: 주어진 roots 소스로 트리 동기화 → π
  assert.equal((await rpOnMirror.verifyLogin(piCanon)).reason, 'stale_root');
  const piMirror = await loginProofAgainst(cia.mirrorAddress);   // Task 9 전까지는 테스트 안에서 syncRevocationTree(…, {untilEpoch: mirror.epoch(), expectRoot: mirror.revRoot()}) 로 직접 만든다
  assert.equal((await rpOnMirror.verifyLogin(piMirror)).ok, true);
});
await t('릴레이 뒤에는 캐노니컬 root 의 π 가 통과한다', async () => {
  await post(`${cia.base}/cia/admin/relay`, {}, { 'X-CIA-Admin-Secret': cia.adminSecret });
  assert.equal((await rpOnMirror.verifyLogin(await loginProofAgainst(cia.logAddress))).ok, true);
});
```
- [ ] **Step 2: 실패 확인** — 첫 케이스에서 `createRpVerifier` 가 거울 주소에 `MODE3_LOG_ABI` 의 `revRoot()` 를 부르는 것은 되지만(getter 같음) … 실제로는 통과할 수 있다. 그래도 Step 3 의 `mode3_rp.js` 변경이 없으면 `test_mode3_demo_stack`·`isolated_mode3_stack` 이 캐노니컬을 읽어 **거울 지연 시나리오가 성립하지 않는다**. 이 Task 의 실패 신호는 `tests/test_mode3_demo_stack.mjs` 가 Task 10 에서 추가할 "거울 지연" 각본이다 — 여기서는 Step 1 테스트가 PASS 하면 그대로 두고 Step 3 를 진행한다(원장에 "RED 없음, 통합 각본이 Task 10" 기록).
- [ ] **Step 3: 구현** — 위 Interfaces 대로. `lib/mode3_rp.js` 헤더 주석에 "b/b‴ 의 root 는 **이 체인의 거울**(V10)" 한 줄.
- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_rp.mjs && node tests/test_mode3_e2e.mjs`(e2e 는 아직 캐노니컬로 π 를 만들고 캐노니컬 검증기를 쓴다 — 그대로 PASS 여야 한다).
- [ ] **Step 5: Commit** — `git commit -m "feat(rp): V10 8/N — RP 는 자기 체인 거울(MODE3_MIRROR_ADDRESS)만 읽는다"`

---

### Task 9: 지갑 에이전트 — 두 provider, 거울 뷰 기준 동기화·증명·캐시

**Files:**
- Modify: `mode3_wallet_agent.js` (env, `syncAll` → 거울 뷰 기준, `registryCheck` 는 캐노니컬 최신, 캐시 키, `/wallet/status`, `registry_unpublished` 대기)
- Modify: `lib/mode3_wallet.js` (`ProofCache.rootKey(chainId, rev, reg)`)
- Modify: `tests/helpers/isolated_mode3_stack.mjs` (지갑 env `MODE3_MIRROR_ADDRESS`, `MODE3_REV_CHAIN_RPC`)
- Test: `tests/test_mode3_wallet_agent.mjs` (3건), `tests/test_mode3_v9_lib.js`(캐시 키 1건)

**Interfaces:**
- env: `MODE3_REV_CHAIN_RPC`(캐노니컬, 기본 `CIA_RPC_URL`), `CIA_LOG_ADDRESS`(캐노니컬), `CIA_RPC_URL`(대상 체인 — 지갑의 기존 `provider`), `MODE3_MIRROR_ADDRESS`(대상 체인 거울). 거울이 없으면 세 라우트는 `503 chain_unavailable`(detail `MODE3_MIRROR_ADDRESS not configured`).
- `syncAll()` → `{ root, regRoot, epoch, head, tree, registry, chainId, mirror: { lastPublishedBlock } , canonical: { root, regRoot, epoch, registry } }`: (1) 거울 뷰를 한 블록에서 읽는다(`revRoot, regRoot, epoch, lastPublishedBlock` at `blockTag = head_X`); (2) `rcl.sync()`(캐노니컬 최신)·`syncRegistryTree(canonProvider, LOG)` 로 캐노니컬 최신 트리; (3) 캐노니컬 최신 root 쌍이 거울과 같으면 그 트리를, 다르면 `rcl.syncAt({ untilEpoch: mirror.epoch, expectRoot: mirror.revRoot })`·`syncRegistryTree(canonProvider, LOG, { untilEpoch, expectRoot: mirror.regRoot })` 로 거울 시점 트리를 쓴다. `registryCheck`(내 슬롯 확인)는 **캐노니컬 최신** `canonical.registry` 로 한다(은퇴·대체 탐지는 빠르게).
- `ProofCache.rootKey(chainId, rev, reg)` → `${chainId}:${rev}:${reg}`(기존 2인자 호출은 전부 3인자로).
- `registry_unpublished` 폴링(30 s): 조건을 "거울 X 의 regRoot 가 내 슬롯을 담은 root 가 될 때까지" 로 — 즉 `syncAll()` 의 거울 시점 `registry` 에서 내 리프가 보일 때까지.
- `/wallet/status`: `chain` 은 대상 체인, 새 필드 `mirror: { address, epoch, lastPublishedBlock }`, `canonical: { rpc, logAddress, epoch }`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_wallet_agent.mjs`(격리 스택, 릴레이 꺼짐):

```js
await t('로그인 π 는 거울의 (revRoot, regRoot) 를 쓴다 — 캐노니컬이 앞서 있어도', async () => {
  await post(`${cia.base}/cia/admin/relay`, {}, admin);       // 내 등록부 리프를 거울에 반영(첫 로그인 전제)
  await revokeOtherUsersSession();                            // 캐노니컬만 epoch +1
  const r = await login();                                    // 기존 헬퍼
  const mirror = new ethers.Contract(cia.mirrorAddress, MODE3_MIRROR_ABI, provider);
  assert.equal(r.body.root, BigInt(await mirror.revRoot()).toString());
  assert.equal(r.body.regRoot, BigInt(await mirror.regRoot()).toString());
});
await t('첫 로그인은 거울에 내 슬롯이 반영될 때까지 registry_unpublished 로 기다렸다가 릴레이 뒤 성공한다', async () => {
  const uid2 = await registerNewUser();                       // 캐노니컬 즉시 게시, 거울은 그대로
  const p = login({ uid: uid2 });                             // 폴링 시작
  await sleep(1500); await post(`${cia.base}/cia/admin/relay`, {}, admin);
  assert.equal((await p).status, 200);
});
await t('/wallet/status 에 mirror·canonical 이 있다', async () => {
  const s = (await get(`${wallet.base}/wallet/status`)).body;
  assert.equal(s.mirror.address.toLowerCase(), cia.mirrorAddress.toLowerCase()); assert.ok(s.canonical.logAddress);
});
```
`tests/test_mode3_v9_lib.js`: `ProofCache.rootKey(31337n, 1n, 2n) === '31337:1:2'`, 2인자 호출은 throw.

- [ ] **Step 2: 실패 확인** — unit: `rootKey` 2인자 → 아직 통과하므로 3인자 테스트가 FAIL(`'1:2'`). chain: 첫 케이스에서 `r.body.root` 가 캐노니컬 root 라 FAIL.
- [ ] **Step 3: 구현** — `mode3_wallet_agent.js`

```js
const MIRROR_ADDRESS = process.env.MODE3_MIRROR_ADDRESS || null;
const REV_RPC = process.env.MODE3_REV_CHAIN_RPC || RPC_URL;
const canonProvider = new ethers.JsonRpcProvider(REV_RPC, undefined, { cacheTimeout: -1 });
const rcl = LOG_ADDRESS ? createRevocationSync({ provider: canonProvider, logAddress: LOG_ADDRESS, cacheFile: RCL_CACHE_FILE, log: … }) : null;
const mirror = MIRROR_ADDRESS ? new ethers.Contract(MIRROR_ADDRESS, MODE3_ROOTS_ABI, provider) : null;
async function mirrorView() {
  const head = BigInt(await provider.getBlockNumber()); const blockTag = Number(head);
  const [revRoot, regRoot, epoch, last] = await Promise.all([mirror.revRoot({ blockTag }), mirror.regRoot({ blockTag }), mirror.epoch({ blockTag }), mirror.lastPublishedBlock({ blockTag })]);
  return { root: BigInt(revRoot), regRoot: BigInt(regRoot), epoch: BigInt(epoch), head, lastPublishedBlock: BigInt(last) };
}
async function syncAll() {
  if (!rcl) throw new Error('CIA_LOG_ADDRESS not configured');
  if (!mirror) throw new Error('MODE3_MIRROR_ADDRESS not configured');
  const mv = await mirrorView();
  let rev, reg;
  for (let i = 0; i < 3; i++) { rev = await rcl.sync(); reg = await syncRegistryTree(canonProvider, LOG_ADDRESS); if (BigInt(rev.head) === BigInt(reg.head)) break; }
  const canonical = { root: rev.root, regRoot: reg.root, epoch: reg.epoch, tree: rev.tree, registry: reg.tree };
  let tree = rev.tree, registry = reg.tree;
  if (rev.root !== mv.root || reg.root !== mv.regRoot) {   // 거울이 뒤처져 있다 — 거울 epoch 시점으로 되감는다
    tree = (await rcl.syncAt({ untilEpoch: mv.epoch, expectRoot: mv.root })).tree;
    registry = (await syncRegistryTree(canonProvider, LOG_ADDRESS, { untilEpoch: mv.epoch, expectRoot: mv.regRoot })).tree;
  }
  return { root: mv.root, regRoot: mv.regRoot, epoch: mv.epoch, head: mv.head, tree, registry, chainId: CHAIN_ID, mirror: { lastPublishedBlock: mv.lastPublishedBlock }, canonical };
}
```
`CHAIN_ID` 는 기동 때 `provider.getNetwork()` 로 한 번. `proveSession` 의 `registryCheck(synced, …)` → `registryCheck({ ...synced, registry: synced.canonical.registry }, …)`(캐노니컬 최신으로 내 슬롯 확인). 캐시 호출 전부 `ProofCache.rootKey(synced.chainId, …)`. `registry_unpublished` 루프: `synced.registry.leaf(reg.slot) === myLeaf` 가 될 때까지(기존 30 s·폴링 간격 유지). `/wallet/status` 필드 추가. `lib/mode3_wallet.js`: `static rootKey(chainId, rev, reg) { if (reg === undefined) throw new Error('ProofCache.rootKey(chainId, rev, reg)'); return `${chainId}:${rev}:${reg}`; }`.

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_v9_lib.js`, 그리고 :8545 에서 `node tests/test_mode3_wallet_agent.mjs && node tests/test_mode3_wallet_snap.mjs && node tests/test_mode3_e2e.mjs`.
- [ ] **Step 5: Commit** — `git commit -m "feat(wallet): V10 9/N — 두 provider, 거울 뷰 기준 동기화·증명, 캐시 키 chainid, status mirror/canonical"`

---

### Task 10: 데모 스택·배포 스크립트·런북·전 구간 각본

**Files:**
- Modify: `scripts/deploy_mode3_log.cjs` (로그 + 거울 배포, `.env` 안내에 `MODE3_MIRROR_ADDRESS`·`CIA_MIRRORS`), `hardhat.config.*`(`networks.hardhat.chainId: Number(process.env.HARDHAT_CHAIN_ID || 31337)` — 선택적 두 번째 노드용)
- Modify: `tests/helpers/isolated_mode3_stack.mjs`(이미 Task 8·9 에서 env 추가 — 여기서는 `relay()` 헬퍼 노출), `tests/test_mode3_demo_stack.mjs`(각본 13·14), `scripts/run_tests.sh`(`tests/test_cia_mirror_relay.mjs` 를 CHAIN 에), `docs/MODE3_DEMO.md`
- Modify: `mode3/cia_admin.html`·`mode3/rp.html`·`mode3/wallet.html` 의 상태 카드 — 거울 epoch/뒤처짐 한 줄(기존 상태 카드가 `/cia/health`·`/rp/info`·`/wallet/status` 를 그리므로 필드만 추가)
- Test: `tests/test_mode3_demo_stack.mjs`, `tests/test_mode3_tour.mjs`(상태 카드 문구 있으면), `tests/test_mode3_demo_strings.js`(i18n 키)

**Interfaces:**
- 각본 13 "거울 지연": 세션 폐기 → 캐노니컬 epoch 상승, 거울 그대로 → 재승인은 캐시 π 로 OK(거울 기준) → `POST /cia/admin/relay` → 재승인이 `revalidate_required` → 새 π → 폐기된 세션은 `revoked_session`.
- 각본 14 "접수증 강제": 자기 폐기 응답의 `receipt` 를 테스트가 `requestRevocation` 으로 올림 → `/cia/publish` 가 `(slot, 0)` 을 실어 통과, `isRetired` true → 되살려 재발급하면 새 슬롯.
- 런북: "처음 한 번" 에 거울 배포·env 세 줄, 선택 절 "폐기 체인을 별도 노드로: `HARDHAT_CHAIN_ID=31338 npx hardhat node --port 8546`, `CIA_RPC_URL=http://127.0.0.1:8546`, `CIA_CHAIN_RPCS=31337=http://127.0.0.1:8545`, 거울은 :8545 에 배포".
- `run_tests.sh` CHAIN 배열에 `tests/test_cia_mirror_relay.mjs` 추가.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_demo_stack.mjs` 에 각본 13·14 를 위 Interfaces 의 흐름 그대로(기존 각본 10~12 의 헬퍼·단언 양식). 각본 13 의 핵심 단언: 릴레이 전 `revalidate` → `cacheHit:true`, 릴레이 후 첫 `revalidate` → `reason:'revalidate_required'`(RP 세션 root 와 거울 root 가 달라짐), 다음 로그인/재검증 → 새 π, 폐기된 세션의 `revalidate` → `revoked_session`.
- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_demo_stack.mjs` → 각본 13 에서 `relay` 헬퍼 없음으로 FAIL.
- [ ] **Step 3: 구현** — `isolated_mode3_stack.mjs` 에 `relay: () => post(`${cia.base}/cia/admin/relay`, {}, admin)`; `deploy_mode3_log.cjs` 에 거울 배포(`Mode3Mirror` 팩토리, `canonicalChainId = (await hre.ethers.provider.getNetwork()).chainId`, 캐노니컬 주소) 와 출력 `.env 에 추가: CIA_LOG_ADDRESS=… / MODE3_MIRROR_ADDRESS=… / CIA_MIRRORS=<chainid>=…`; 런북 §"처음 한 번"·§환경 변수 표·§각본 표(13·14)·§테스트 목록 갱신; 상태 카드 문구 추가(i18n 키 `aa_mirror_line` 등은 `tests/test_mode3_demo_strings.js` 의 키 목록에 넣는다).
- [ ] **Step 4: 통과 확인** — `bash scripts/run_tests.sh chain` 전체, `npm test`(unit+circuit), `bash scripts/run_tests.sh contract`, `bash scripts/run_tests.sh browser`(Chrome 있으면), `snap`.
- [ ] **Step 5: Commit** — `git commit -m "feat(mode3): V10 10/N — 배포 스크립트(로그+거울), 데모 각본 13·14, 런북, 상태 카드"`

---

### Task 11: 벤치 행과 결과 문서

**Files:**
- Modify: `scripts/bench_mode3_onchain.mjs` (거울 배포 gas, 거울 갱신 gas, 접수증 제출 gas, 강제 게시 gas 행)
- Create: `results/mode3_v10_revocation_chain_<YYYYMMDD>.md`

- [ ] **Step 1: 벤치에 측정 추가** — `deployMode3Mirror` 가스, `relayToMirror` 가스(N=10 중앙값), `requestRevocation` 가스, pending 1개를 실은 `publish` 가스. 출력 표에 네 행.
- [ ] **Step 2: 실행** — `node scripts/bench_mode3_onchain.mjs` (:8545, 격리 CIA). 결과를 `results/` 새 파일에 V9 문서와 같은 양식으로(환경·N·중앙값 방식 각주).
- [ ] **Step 3: Commit** — `git commit -m "bench(mode3): V10 11/N — 거울·접수증·강제 게시 gas"`

---

## 자체 검토

1. **스펙 커버리지**: §2 구성 요소(T1·T3 컨트랙트, T5·T6 CIA, T8 RP, T9 지갑) ✔. §3 결정 1(T1 다이제스트, T3 거울 세 해시) ✔. §4 결정 2(T2 대기열·강제·은퇴, T5 접수증·따르기·새 슬롯, T10 각본 14) ✔; "세션 폐기 불변" 은 어느 Task 도 건드리지 않음 ✔. §5 결정 3(T6 하트비트 주기·캐노니컬 하트비트 선행, T7 untilEpoch, T8 RP 거울, T9 거울 뷰·캐시 키 chainid, T10 각본 13) ✔. §6 변경 범위의 `Mode3Wallet` 타입(T1), 데모 스택·run_tests(T10), 문서(T10 런북; 논문·슬라이드는 계획 밖 — 사용자 요청 시) ✔. §7 별도 제안(sk_u 제거·시드 파생)은 **의도적으로 제외**. §8 질문 기본값: hardhat 두 번째 노드는 선택(T10 런북), H=50·MAX=100(Global Constraints), 접수증은 응답 + `acct.receipt`(T5).
2. **플레이스홀더**: T3 의 `_recover` "같은 본문" 은 Mode3Log 의 함수를 그대로 복사하라는 뜻(코드는 Task 1 의 파일에 있다). T8 Step 2 의 "RED 없음" 은 명시적으로 적었다.
3. **타입 일관성**: `publishV3` 반환 `{ sig, p }` 를 T6·T8·T10 이 그대로 씀; `entryHashes` 의 `{ hLeaves, hIdx, hSlots }` 가 거울 `publish` 인자 순서와 같음; `ProofCache.rootKey(chainId, rev, reg)` 3인자 통일; `receipt` 객체 필드(`slot, epochAtRequest, requestedAt, sig, canonicalChainId, canonicalLogAddress`) 가 T2 `verifyReceipt(params)` 의 키와 같음.

**실행 중 알려진 빨간 구간**: Task 1 뒤 chain 그룹(V2 삭제) → Task 4·5 가 되돌린다. SDD 원장에 "T1~T4 사이 chain 그룹 RED 는 설계된 상태" 로 적어 둔다.
