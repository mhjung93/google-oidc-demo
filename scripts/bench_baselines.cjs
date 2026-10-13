// zk-Delegation(Mode 3) 논문의 비용 표에 나란히 둘 "바닥값(floor)" 기준선 — zk 증명도, 외부 IdP 도 전혀
// 쓰지 않는 평범한 연산들의 비용을 같은 자리에서 잰다.
//   npx hardhat run scripts/bench_baselines.cjs
//
// 반드시 인프로세스 hardhat 네트워크로 돈다(--network 를 주지 말 것) — :8545 의 영속 노드를 전혀 건드리지
// 않는다. 측정 항목(각 절이 "왜"를 설명한다):
//   (A) EOA→EOA 값 전송 gas — 체인에서 가능한 가장 싼 트랜잭션. 21,000 이 나오면 이 머신 기준점이 맞다는 뜻.
//   (B) Mode3Wallet.execute 를 "무엇이든 통과시키는" 검증자(contracts/test/AcceptAllPiCredVerifier.sol)로
//       잰다. 실제 PiCredVerifier 대신 꽂으면 Groth16 pairing·스칼라곱 비용이 완전히 빠지고, 서명 복구
//       (ecrecover)·_checkStatement 대조·이벤트 3개 같은 "계정 추상화 오버헤드"만 남는다. AcceptAll 검증자는
//       인자를 전혀 보지 않고 항상 true 를 돌려주므로(contracts/test/AcceptAllPiCredVerifier.sol), 이 절은
//       build/mode3 의 zkey·wasm 이나 snarkjs 증명 생성이 전혀 필요 없다 — pub[]은 지갑의 온체인 대조
//       (_checkStatement)만 만족하면 되는 평범한 숫자들이다.
//   (C) 평범한 서명 검증(Node crypto): RS256(OIDC RP 가 ID 토큰에 매번 하는 것), Ed25519, ECDSA secp256k1
//       복구(ethers.recoverAddress — EOA 트랜잭션이 오프체인에서 무는 것과 같은 연산).
//   (D) EdDSA-Poseidon(Baby Jubjub) 검증(circomlibjs) — 우리 회로가 안에서 검증하는 서명과 같은 것. 참고용.
//
// 결과 해석(AA 오버헤드·Groth16 비용 분리)은 이 스크립트가 아니라 결과 파일(results/baselines_*.md)에
// 적는다 — 실 검증기 조건의 477,220(results/mode3_v11_figure_protocol_20261013.md)과 비교해야 하는데,
// 그 숫자를 이 범용 스크립트에 박아 두면 그 결과 파일이 갱신될 때마다 같이 썩는다.
const hre = require("hardhat");
const crypto = require("crypto");

const N_SIG = 1000;
const N_EDDSA = 200;
const WARMUP_SIG = 50;
const WARMUP_EDDSA = 20;

// Mode3ReferenceCode.test.mjs 의 ARGS 패턴과 같은 placeholder 값(실제 arid·pk_CIA·pk_trace 가 아니어도
// _checkStatement 가 보는 것은 "지갑 생성자에 박힌 값 == pub[] 의 값" 뿐이라 숫자 자체는 임의로 고른다).
const ARID = 1n, PK_CIA_X = 2n, PK_CIA_Y = 3n, PK_TRACE_X = 4n, PK_TRACE_Y = 5n;
const MAX_ROOT_AGE = 100n, MAX_LIFETIME = 400n;
const REV_ROOT = 111n, REG_ROOT = 222n;

const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const mean = (a) => a.reduce((s, x) => s + x, 0) / a.length;
const fmtGas = (a) => `${med(a).toLocaleString()} (${Math.min(...a).toLocaleString()}–${Math.max(...a).toLocaleString()})`;
const fmtUs = (a) => `중앙값 ${med(a).toFixed(1)} µs / 평균 ${mean(a).toFixed(1)} µs (최소 ${Math.min(...a).toFixed(1)}–최대 ${Math.max(...a).toFixed(1)})`;

function assertInProcessNetwork() {
  if (hre.network.name !== "hardhat") {
    throw new Error(
      "이 벤치는 인프로세스 hardhat 네트워크 전용이다. --network 를 주지 말고 실행할 것:\n" +
      "  npx hardhat run scripts/bench_baselines.cjs\n" +
      "(--network localhost 로 돌리면 :8545 의 영속 노드 상태를 건드리게 된다.)"
    );
  }
}

// ── (A) EOA → EOA 값 전송 ────────────────────────────────────────────────
async function benchTransfer() {
  const [a, b] = await hre.ethers.getSigners();
  const send = async () => Number((await (await a.sendTransaction({ to: b.address, value: 1n })).wait()).gasUsed);
  const cold = await send();
  const warm = await send();
  return { cold, warm };
}

// ── (B) Mode3Wallet.execute, AcceptAll 검증자 ──────────────────────────
function buildPub({ PUB_INDEX }, { ppid, pkI, maxHeight, chainId }) {
  const pub = new Array(Number(PUB_INDEX.COUNT)).fill(0n);
  pub[PUB_INDEX.PPID] = ppid;
  pub[PUB_INDEX.ARID] = ARID;
  pub[PUB_INDEX.PK_I] = pkI;
  pub[PUB_INDEX.MAX_HEIGHT] = maxHeight;
  pub[PUB_INDEX.CHAINID] = chainId;
  pub[PUB_INDEX.ALLOW_AGENT] = 0n;
  pub[PUB_INDEX.REV_ROOT] = REV_ROOT;
  pub[PUB_INDEX.REG_ROOT] = REG_ROOT;
  pub[PUB_INDEX.PK_CIA_X] = PK_CIA_X;
  pub[PUB_INDEX.PK_CIA_Y] = PK_CIA_Y;
  pub[PUB_INDEX.PK_TRACE_X] = PK_TRACE_X;
  pub[PUB_INDEX.PK_TRACE_Y] = PK_TRACE_Y;
  pub[PUB_INDEX.TAG_C1_X] = 1n;   // (0,1) 조합만 피하면 됨(BadTag) — 그 외 값은 온체인이 대조하지 않는다.
  pub[PUB_INDEX.TAG_C1_Y] = 2n;
  pub[PUB_INDEX.TAG_C2] = 3n;
  // DISC_MASK..SET_ROOT(15..29) = 0(공개 없음·집합 없음), AUID_S..R_S(30..32) = 0(온체인 미검사) — fill(0n) 그대로.
  return pub;
}

async function executeOnce(mode3, wallet, { ppid, to, value = 0n, nonce }) {
  const { PUB_INDEX, signPayload, statementDigestFields } = mode3;
  const session = hre.ethers.Wallet.createRandom();   // 세션(π 의 pk_i)마다 새 임시 키 — 실제 로그인마다 새 세션키를 쓰는 것과 같다.
  const net = await hre.ethers.provider.getNetwork();
  const blockNow = BigInt(await hre.ethers.provider.getBlockNumber());
  const pub = buildPub({ PUB_INDEX }, { ppid, pkI: BigInt(session.address), maxHeight: blockNow + 300n, chainId: net.chainId });
  const stmt = statementDigestFields(pub);
  const payload = { to, value, data: "0x", nonce };
  const sig = signPayload(session, { chainId: net.chainId, wallet: wallet.target, ...payload, ...stmt });
  const A = [0n, 0n], B = [[0n, 0n], [0n, 0n]], C = [0n, 0n];   // AcceptAllPiCredVerifier 는 보지 않는다.
  const receipt = await (await wallet.execute(payload, sig, A, B, C, pub)).wait();
  return Number(receipt.gasUsed);
}

async function benchMode3Wallet() {
  const mode3 = await import("../lib/mode3_onchain.js");
  const { factoryAt, walletAt } = mode3;
  const [deployer] = await hre.ethers.getSigners();

  const verifier = await (await hre.ethers.getContractFactory("AcceptAllPiCredVerifier")).deploy();
  const log = await (await hre.ethers.getContractFactory("Mode3Log")).deploy(
    deployer.address, hre.ethers.toBeHex(REV_ROOT, 32), hre.ethers.toBeHex(REG_ROOT, 32),
  );
  const factoryDeployed = await (await hre.ethers.getContractFactory("Mode3WalletFactory")).deploy(
    await verifier.getAddress(), ARID, PK_CIA_X, PK_CIA_Y, PK_TRACE_X, PK_TRACE_Y, await log.getAddress(), MAX_ROOT_AGE, MAX_LIFETIME,
  );
  const factory = factoryAt(await factoryDeployed.getAddress(), deployer);

  // 지갑 1: to=새 EOA, value=0, mask=0, set 없음 — bench_mode3_onchain.mjs 의 "execute gas(mask=0, 캐시 π)" 와 같은 모양.
  const ppid1 = 123456789n;
  const walletAddr1 = await factory.computeAddress(ppid1);
  await (await factory.deploy(ppid1)).wait();
  const wallet1 = walletAt(walletAddr1, deployer);

  const first = await executeOnce(mode3, wallet1, { ppid: ppid1, to: hre.ethers.Wallet.createRandom().address, value: 0n, nonce: await wallet1.nonce() });
  const cached = [];
  for (let i = 0; i < 5; i++) {
    cached.push(await executeOnce(mode3, wallet1, {
      ppid: ppid1, to: hre.ethers.Wallet.createRandom().address, value: 0n, nonce: await wallet1.nonce(),
    }));
  }

  // 지갑 2: test/Mode3Wallet.test.mjs "정상 실행" 조건 재현 — 갓 배포한 지갑의 첫 execute, 손대지 않은(0 잔액·
  // 한 번도 안 쓰인) 주소로 value=0.1 ETH. 새 계정 생성 비용(EIP-2929)이 얹히므로 지갑 1 과는 분리한다.
  const ppid2 = 987654321n;
  const walletAddr2 = await factory.computeAddress(ppid2);
  await (await deployer.sendTransaction({ to: walletAddr2, value: hre.ethers.parseEther("1") })).wait();
  await (await factory.deploy(ppid2)).wait();
  const wallet2 = walletAt(walletAddr2, deployer);
  const value01 = await executeOnce(mode3, wallet2, {
    ppid: ppid2, to: hre.ethers.Wallet.createRandom().address, value: hre.ethers.parseEther("0.1"), nonce: await wallet2.nonce(),
  });

  return { first, cached, value01 };
}

// ── (C) 평범한 서명 검증(Node crypto) ───────────────────────────────────
function timeLoop(n, warmup, fn) {
  for (let i = 0; i < warmup; i++) fn();
  const us = [];
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    fn();
    const t1 = process.hrtime.bigint();
    us.push(Number(t1 - t0) / 1000);
  }
  return us;
}

function benchConventionalSigs() {
  // RS256(RSA-2048) — 평범한 OIDC RP 가 ID 토큰마다 하는 것과 같은 연산. 페이로드는 JWT 와 비슷한 크기(~800B,
  // base64url 전 header.payload 크기 흉내)로 자체 생성한다 — 실제 토큰 파일은 읽지 않는다.
  const rsaPair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaPayload = crypto.randomBytes(800);
  const rsaSig = crypto.sign("RSA-SHA256", rsaPayload, rsaPair.privateKey);
  const rs256 = timeLoop(N_SIG, WARMUP_SIG, () => crypto.verify("RSA-SHA256", rsaPayload, rsaPair.publicKey, rsaSig));

  // Ed25519
  const edPair = crypto.generateKeyPairSync("ed25519");
  const edPayload = crypto.randomBytes(800);
  const edSig = crypto.sign(null, edPayload, edPair.privateKey);
  const ed25519 = timeLoop(N_SIG, WARMUP_SIG, () => crypto.verify(null, edPayload, edPair.publicKey, edSig));

  // ECDSA secp256k1 복구(ecrecover) — EOA 트랜잭션 서명을 오프체인에서 검증할 때의 비용과 같은 연산.
  const w = hre.ethers.Wallet.createRandom();
  const digest = hre.ethers.keccak256(crypto.randomBytes(32));
  const ecSig = w.signingKey.sign(digest).serialized;
  const ecrecover = timeLoop(N_SIG, WARMUP_SIG, () => hre.ethers.recoverAddress(digest, ecSig));

  return { rs256, ed25519, ecrecover };
}

// ── (D) EdDSA-Poseidon(Baby Jubjub) 검증 — 우리 회로가 안에서 검증하는 서명과 같은 것 ─────────
async function benchEddsaPoseidon() {
  const { buildEddsa, buildPoseidon } = await import("circomlibjs");
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const prv = crypto.randomBytes(32);
  const pub = eddsa.prv2pub(prv);
  const msg = poseidon([1n, 2n, 3n]);   // 임의 필드 원소 해시 — 서명 검증 비용만 보는 것이라 메시지 내용은 무관.
  const sig = eddsa.signPoseidon(prv, msg);
  return timeLoop(N_EDDSA, WARMUP_EDDSA, () => eddsa.verifyPoseidon(msg, sig, pub));
}

async function main() {
  assertInProcessNetwork();

  const transfer = await benchTransfer();
  const wallet = await benchMode3Wallet();
  const sigs = benchConventionalSigs();
  const eddsa = await benchEddsaPoseidon();

  console.log("");
  console.log("## (A) EOA → EOA 값 전송 gas");
  console.log("");
  console.log("| 조건 | gas |");
  console.log("|:--|---:|");
  console.log(`| 1차(cold) | ${transfer.cold.toLocaleString()} |`);
  console.log(`| 2차(warm) | ${transfer.warm.toLocaleString()} |`);

  console.log("");
  console.log("## (B) Mode3Wallet.execute gas — AcceptAllPiCredVerifier(검증 비용 제거, AA 오버헤드만)");
  console.log("");
  console.log("| 조건 | gas |");
  console.log("|:--|---:|");
  console.log(`| 첫 호출(to=새 EOA, value=0, mask=0) | ${wallet.first.toLocaleString()} |`);
  console.log(`| mask=0·캐시 π 와 같은 모양(N=5, 중앙값(최소–최대)) | ${fmtGas(wallet.cached)} |`);
  console.log(`| value=0.1 ETH → 손대지 않은 주소(test/Mode3Wallet.test.mjs "정상 실행" 조건 재현) | ${wallet.value01.toLocaleString()} |`);

  console.log("");
  console.log(`## (C) 평범한 서명 검증 시간(Node crypto, N=${N_SIG})`);
  console.log("");
  console.log("| 방식 | 시간 |");
  console.log("|:--|:--|");
  console.log(`| RS256(RSA-2048) | ${fmtUs(sigs.rs256)} |`);
  console.log(`| Ed25519 | ${fmtUs(sigs.ed25519)} |`);
  console.log(`| ECDSA secp256k1 복구(ethers.recoverAddress) | ${fmtUs(sigs.ecrecover)} |`);

  console.log("");
  console.log(`## (D) EdDSA-Poseidon(Baby Jubjub) 검증 시간(circomlibjs, N=${N_EDDSA})`);
  console.log("");
  console.log("| 방식 | 시간 |");
  console.log("|:--|:--|");
  console.log(`| EdDSA-Poseidon verify | ${fmtUs(eddsa)} |`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
