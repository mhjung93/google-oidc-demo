const hre = require("hardhat");
const { getIdPSigner, rootToBytes32 } = require("./revocation_idp.cjs");

// hardhat.config.cjs에 networks 블록이 없어 defaultNetwork가 "hardhat"이다.
// push_revocation_root.cjs와 같은 이유로, --network 없이 실행하면 명령 종료와
// 함께 사라지는 임시 인프로세스 체인에 프루닝 root를 게시하게 되어 실제 8545
// 체인의 RevocationRegistry에는 반영되지 않는다.
function assertPersistentNetwork() {
  if (hre.network.name === "hardhat") {
    throw new Error(
      '이 스크립트는 --network localhost 없이 실행되었습니다. ' +
      'defaultNetwork가 "hardhat"이라 트랜잭션이 명령 종료와 함께 사라지는 ' +
      '임시 인프로세스 체인에 들어갑니다. 다음처럼 실행하세요:\n' +
      '  npx hardhat run scripts/revocation_sweep.cjs --network localhost'
    );
  }
}

async function callIdPAdmin(idpBaseUrl, adminSecret, pathname, body) {
  let res;
  try {
    res = await fetch(`${idpBaseUrl}${pathname}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-IdP-Admin-Secret": adminSecret },
      body: JSON.stringify(body ?? {}),
    });
  } catch (err) {
    throw new Error(`IdP(${idpBaseUrl})에 연결할 수 없어 ${pathname}을 호출하지 못했습니다: ${err.message}`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${pathname} failed (${idpBaseUrl}): ${res.status} ${text}`);
  }
  return res.json();
}

// 로컬 데모 체인(hardhat node)은 트랜잭션이 있을 때만 블록을 찍는다. 즉 이
// 스크립트가 벽시계 기준으로 주기 실행돼도, 체인 블록 번호는 다른 트랜잭션
// 활동이 없으면 벽시계보다 "느리게" 늙는다. GRACE_BLOCKS는 블록 수 기준이므로
// 이 경우 실제 grace window는 벽시계 기준 계산보다 항상 더 넉넉하다 — 안전한
// 방향의 오차다(반대 방향, 즉 체인이 벽시계보다 빨리 늙는 경우라면 위험했을 것).
const BLOCK_TIME_SECONDS_ASSUMED = 12; // spec/컨트랙트 주석의 가정치. GRACE_BLOCKS 자체는 온체인에서 읽는다.
const DEFAULT_SAFETY_FACTOR = 4; // interval * factor <= GRACE_BLOCKS * 12s 이어야 기동 허용
const DEFAULT_FAILURE_ALERT_THRESHOLD = 3; // 연속 이 횟수 이상 실패하면 경고 배너 출력
const SLEEP_POLL_MS = 500; // 종료 신호를 얼마나 자주 확인하며 대기할지

// 폐기 게시 한 사이클(batch publish). IdP에 대기 중인 폐기를 반영하고 만료된 리프를
// 정리한 다음 그 root를 온체인에 게시한다.
//
// 순서가 핵심이다: prepare(계산만) -> pushRoot(온체인 확정) -> commit(IdP 전진).
// IdP를 먼저 전진시키면 push가 실패했을 때 '게시되지 않은 root'를 지갑이 받아가
// 정상 사용자 전원의 execute()가 StaleRevocationRoot로 막힌다. push가 확정된
// 뒤에만 commit하므로 그 창이 존재하지 않는다.
//
// 이 순서 덕분에 사이클이 어느 지점에서 중단돼도(프로세스 kill, SIGINT 등) 안전하다:
//   - prepare 이후 push 이전에 중단 -> IdP·온체인 둘 다 아무 변화 없음. 다음 사이클이
//     처음부터 다시 prepare한다.
//   - push 이후 commit 이전에 중단 -> 온체인 root는 이미 최신으로 확정됐고, IdP는
//     아직 이전 상태를 서빙 중이므로 지갑은 "이전(그러나 여전히 유효한) root" 기준
//     witness를 계속 받는다. 다음 사이클이 같은 expectedRoot로 prepare를 재계산해
//     commit을 마저 진행한다(IdP가 게시된 상태만 서빙하므로 재계산 결과는 같다).
// 즉 안전한 중단 지점이 이미 두 곳 다 보장돼 있으므로, 정상 종료 처리는 "사이클을
// 강제로 끝까지 밀어붙이는" 로직이 필요 없고 진행 중인 사이클이 자연스럽게 끝나도록
// 기다렸다가 다음 사이클을 시작하지 않는 것으로 충분하다.
async function runOneCycle(ctx) {
  const { idpBaseUrl, adminSecret, registry, hre: hreRef } = ctx;

  // 1) prepare — 다음 게시 후보 root를 계산만 한다. IdP 게시 상태는 그대로다.
  const prepared = await callIdPAdmin(idpBaseUrl, adminSecret, "/idp/publish/prepare");
  const expectedRoot = prepared.expectedRoot;
  if (expectedRoot === undefined || expectedRoot === null) {
    throw new Error(`/idp/publish/prepare 응답에 expectedRoot가 없습니다 (${idpBaseUrl})`);
  }
  console.log(
    `1/3 prepare: added=${prepared.added}, removed=${prepared.removed}, ` +
    `leaves=${prepared.leafCount}, pending=${prepared.pendingCount}`
  );
  console.log(`    currentRoot=${prepared.currentRoot}`);
  console.log(`    expectedRoot=${expectedRoot}`);

  // 2) pushRoot — 온체인에 게시하고 영수증까지 기다린다.
  const rootHex = rootToBytes32(hreRef, String(expectedRoot));

  // push_revocation_root.cjs와 동일하게 중복 게시 가드는 두지 않는다(dd75591에서
  // 의도적으로 제거됨). 추가·제거가 0건이어도(heartbeat) 이 root를 다시 push해서
  // pushedAt을 갱신해야 RevocationRegistry의 GRACE_BLOCKS 만료로 정상 사용자가
  // 막히는 일을 막는다.
  const tx = await registry.pushRoot(rootHex);
  const receipt = await tx.wait();
  console.log(`2/3 pushRoot: ${rootHex} (block ${receipt.blockNumber}, tx ${receipt.hash})`);

  // 3) commit — push가 확정된 뒤에만 IdP를 전진시킨다.
  const committed = await callIdPAdmin(idpBaseUrl, adminSecret, "/idp/publish/commit", {
    root: String(expectedRoot),
  });
  console.log(
    `3/3 commit: published root=${committed.root}, leaves=${committed.leafCount}, ` +
    `pending=${committed.pendingCount}`
  );

  if (String(committed.root) !== String(expectedRoot)) {
    throw new Error(
      `commit이 반영한 root(${committed.root})가 게시한 root(${expectedRoot})와 다릅니다. ` +
      `IdP 상태와 온체인 root가 어긋났습니다.`
    );
  }
  console.log("Published revocation root:", rootHex);
}

// 배포된 RevocationRegistry에서 GRACE_BLOCKS를 읽어, 설정된 주기가 안전한지 검사한다.
// GRACE_BLOCKS는 컨트랙트 상수이므로 여기서 다시 숫자로 박지 않고 매번 온체인에서
// 읽는다 — 재배포로 값이 바뀌어도 이 스크립트를 고칠 필요가 없게 하기 위함이다.
//
// 안전계수(safetyFactor)를 두는 이유: 주기가 GRACE_BLOCKS 상한에 바짝 붙어 있으면
// 사이클이 단 한두 번만 연속 실패해도(네트워크 순단, IdP 재시작 등) grace window가
// 만료돼 전원이 막힌다. interval * safetyFactor <= capSeconds를 요구하면, 적어도
// (safetyFactor - 1)번 연속 실패까지는 다음 성공 사이클이 grace window 안에서
// 갱신할 여지가 남는다.
async function checkIntervalSafety(registry, intervalSeconds, safetyFactor) {
  const graceBlocksRaw = await registry.GRACE_BLOCKS();
  const graceBlocks = Number(graceBlocksRaw);
  const capSeconds = graceBlocks * BLOCK_TIME_SECONDS_ASSUMED;
  const maxSafeIntervalSeconds = capSeconds / safetyFactor;

  if (!(intervalSeconds > 0) || intervalSeconds > maxSafeIntervalSeconds) {
    throw new Error(
      `REVOCATION_SWEEP_INTERVAL_SECONDS=${intervalSeconds}가 안전 상한을 초과합니다.\n` +
      `  온체인 GRACE_BLOCKS=${graceBlocks} (블록당 ${BLOCK_TIME_SECONDS_ASSUMED}초 가정 시 ` +
      `${capSeconds}초 상한), 안전계수=${safetyFactor} 적용 시 허용 간격은 최대 ` +
      `${maxSafeIntervalSeconds.toFixed(1)}초입니다.\n` +
      `  간격을 줄이거나(REVOCATION_SWEEP_INTERVAL_SECONDS), 안전계수를 재검토하세요 ` +
      `(REVOCATION_SWEEP_SAFETY_FACTOR, 기본값 ${DEFAULT_SAFETY_FACTOR}).\n` +
      `  이 간격으로 기동하면 사이클이 몇 번만 연속 실패해도 GRACE_BLOCKS 만료로 ` +
      `정상 사용자 전원의 /submitTransaction이 막힙니다.`
    );
  }

  console.log(
    `[sweep] 안전 가드 통과: interval=${intervalSeconds}s, GRACE_BLOCKS=${graceBlocks} ` +
    `(가정 ${BLOCK_TIME_SECONDS_ASSUMED}s/block → 상한 ${capSeconds}s), ` +
    `safetyFactor=${safetyFactor} → 허용 간격 상한=${maxSafeIntervalSeconds.toFixed(1)}s`
  );
}

// shuttingDown()이 true가 되거나 ms가 지날 때까지 짧은 간격으로 깨어나며 대기한다.
// setTimeout(ms) 하나로 통짜로 자면 SIGINT를 받아도 최대 interval만큼 종료가 늦어지므로,
// SLEEP_POLL_MS 단위로 쪼개 즉시 반응하게 한다.
function sleepInterruptible(ms, shuttingDown) {
  return new Promise((resolve) => {
    const deadline = Date.now() + ms;
    const tick = () => {
      if (shuttingDown() || Date.now() >= deadline) {
        resolve();
        return;
      }
      setTimeout(tick, Math.min(SLEEP_POLL_MS, deadline - Date.now()));
    };
    tick();
  });
}

// 주기 모드: prepare -> push -> commit 사이클을 interval마다 무한 반복한다.
// 한 사이클의 실패가 데몬 자체를 죽이면 안 된다 — 그러면 fail-closed 설계상
// 다음 사이클도 영영 오지 않고 전원이 막힌 채로 방치된다. 그래서 사이클 실패는
// catch해서 로그만 남기고 다음 주기에 재시도한다. 다만 실패가 연속되면(=진짜
// 문제일 가능성이 높음) 조용히 넘어가지 않고 눈에 띄는 경고를 반복 출력한다.
async function runLoop(ctx, intervalSeconds, failureAlertThreshold) {
  let shuttingDown = false;

  const onSignal = (sig) => {
    if (shuttingDown) {
      console.log(`[sweep] ${sig} 재수신 — 즉시 종료합니다.`);
      process.exit(1);
    }
    shuttingDown = true;
    console.log(
      `[sweep] ${sig} 수신 — 진행 중인 사이클을 마치고 종료합니다. ` +
      `(prepare~push 전이면 아무 변화 없이 끝나고, push~commit 전이면 온체인이 이미 ` +
      `최신이라 지갑은 계속 유효한 root로 동작합니다 — 어느 지점이든 안전. 재신호 시 즉시 종료.)`
    );
  };
  process.on("SIGINT", () => onSignal("SIGINT"));
  process.on("SIGTERM", () => onSignal("SIGTERM"));

  let consecutiveFailures = 0;
  let cycleCount = 0;

  while (!shuttingDown) {
    cycleCount += 1;
    console.log(`\n[sweep] ===== 사이클 #${cycleCount} 시작 (${new Date().toISOString()}) =====`);
    try {
      await runOneCycle(ctx);
      if (consecutiveFailures > 0) {
        console.log(`[sweep] 복구됨 — 연속 실패 ${consecutiveFailures}회 이후 사이클 #${cycleCount} 성공.`);
      }
      consecutiveFailures = 0;
    } catch (err) {
      consecutiveFailures += 1;
      console.error(
        `[sweep] 사이클 #${cycleCount} 실패 (연속 ${consecutiveFailures}회):`,
        err && err.message ? err.message : err
      );
      if (consecutiveFailures >= failureAlertThreshold) {
        console.error(
          "\n" + "!".repeat(70) + "\n" +
          `[sweep] 경고: 연속 ${consecutiveFailures}회 실패. GRACE_BLOCKS 만료 시 정상 사용자 ` +
          "전원의 /submitTransaction이 막힙니다. 운영자 확인이 필요합니다.\n" +
          "!".repeat(70) + "\n"
        );
      }
    }

    if (shuttingDown) break;
    console.log(`[sweep] 다음 사이클까지 ${intervalSeconds}초 대기...`);
    await sleepInterruptible(intervalSeconds * 1000, () => shuttingDown);
  }

  console.log(`[sweep] 정상 종료 (총 ${cycleCount}사이클 실행, 연속 실패 ${consecutiveFailures}회 상태로 종료).`);
}

async function main() {
  assertPersistentNetwork();
  const idpBaseUrl = process.env.CUSTOM_IDP_BASE_URL || "http://127.0.0.1:4000";
  const registryAddress = process.env.REVOCATION_REGISTRY_ADDRESS;
  if (!registryAddress) throw new Error("REVOCATION_REGISTRY_ADDRESS is required");

  const adminSecret = process.env.IDP_ADMIN_SECRET;
  if (!adminSecret) {
    throw new Error(
      "IDP_ADMIN_SECRET is required (must match the value custom_idp.js was started with) " +
      "— POST /idp/publish/prepare and /idp/publish/commit are admin-only endpoints."
    );
  }

  // onlyIdP 주소는 REVOCATION_IDP_ADDRESS로 명시한다 — 배포 스크립트/
  // push_revocation_root.cjs와 같은 값을 써야 pushRoot가 NotIdP로 revert하지 않는다.
  const idpSigner = await getIdPSigner(hre);
  const registry = await hre.ethers.getContractAt("RevocationRegistry", registryAddress, idpSigner);
  const ctx = { idpBaseUrl, adminSecret, registry, hre };

  // REVOCATION_SWEEP_INTERVAL_SECONDS가 없으면 기존과 동일하게 1회만 실행하고 끝난다
  // (회귀 없음). 값이 있으면 그 초 간격으로 무기한 반복하는 데몬 모드로 들어간다.
  const intervalRaw = process.env.REVOCATION_SWEEP_INTERVAL_SECONDS;
  if (!intervalRaw) {
    await runOneCycle(ctx);
    return;
  }

  const intervalSeconds = Number(intervalRaw);
  if (!Number.isFinite(intervalSeconds) || intervalSeconds <= 0) {
    throw new Error(`REVOCATION_SWEEP_INTERVAL_SECONDS는 양수(초)여야 합니다: ${intervalRaw}`);
  }

  const safetyFactorRaw = process.env.REVOCATION_SWEEP_SAFETY_FACTOR;
  const safetyFactor = safetyFactorRaw !== undefined ? Number(safetyFactorRaw) : DEFAULT_SAFETY_FACTOR;
  if (!Number.isFinite(safetyFactor) || safetyFactor <= 1) {
    throw new Error(`REVOCATION_SWEEP_SAFETY_FACTOR는 1보다 큰 수여야 합니다: ${safetyFactorRaw}`);
  }

  await checkIntervalSafety(registry, intervalSeconds, safetyFactor);

  const failureAlertThresholdRaw = process.env.REVOCATION_SWEEP_FAILURE_ALERT_THRESHOLD;
  const failureAlertThreshold =
    failureAlertThresholdRaw !== undefined ? Number(failureAlertThresholdRaw) : DEFAULT_FAILURE_ALERT_THRESHOLD;
  if (!Number.isFinite(failureAlertThreshold) || failureAlertThreshold <= 0) {
    throw new Error(`REVOCATION_SWEEP_FAILURE_ALERT_THRESHOLD는 양수여야 합니다: ${failureAlertThresholdRaw}`);
  }

  console.log(`[sweep] 데몬 모드 시작: interval=${intervalSeconds}s, failureAlertThreshold=${failureAlertThreshold}`);
  await runLoop(ctx, intervalSeconds, failureAlertThreshold);
}

main().catch((e) => { console.error(e); process.exit(1); });
