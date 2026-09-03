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

const DEFAULT_FAILURE_ALERT_THRESHOLD = 3; // 연속 이 횟수 이상 실패하면 경고 배너 출력
const SLEEP_POLL_MS = 500; // 종료 신호를 얼마나 자주 확인하며 대기할지
const COMMIT_RETRY_ATTEMPTS = 3; // 최초 시도 이후 추가로 시도할 횟수
const COMMIT_RETRY_DELAY_MS = 2000; // 재시도 사이 대기. grace window가 없어 이 창이 곧 전면 장애 시간이므로 짧게 잡는다.

// 폐기 게시 한 사이클(batch publish). IdP에 대기 중인 폐기를 반영하고 만료된 리프를
// 정리한 다음 그 root를 온체인에 게시한다.
//
// 순서가 핵심이다: prepare(계산만) -> pushRoot(온체인 확정) -> commit(IdP 전진).
// IdP를 먼저 전진시키면 push가 실패했을 때 '게시되지 않은 root'를 지갑이 받아가
// 정상 사용자 전원의 execute()가 StaleRevocationRoot로 막힌다. push가 확정된
// 뒤에만 commit하므로 그 창이 존재하지 않는다.
//
// 이 순서로 중단 지점 중 하나는 안전하지만, 다른 하나는 grace window가 없어진 뒤로
// 더 이상 안전하지 않다(프로세스 kill, SIGINT 등으로 중단됐을 때):
//   - prepare 이후 push 이전에 중단 -> IdP·온체인 둘 다 아무 변화 없음. 다음 사이클이
//     처음부터 다시 prepare한다. (안전)
//   - push 이후 commit 이전에 중단 -> 온체인 latestRoot는 이미 새 root로 확정됐는데
//     IdP는 아직 이전 리프 집합을 서빙 중이다. grace window가 없으므로 지갑이 그
//     이전 리프 집합으로 만드는 root는 더 이상 latestRoot와 같지 않고, 그 사이
//     StaleRevocationRoot로 전원(폐기와 무관한 사용자 포함)이 막힌다 — "안전한
//     중단 지점"이 아니라 전면 장애 구간이다. 그래서 commit은 실패 시 짧은 간격으로
//     즉시 재시도해 이 창을 최대한 좁힌다(아래 COMMIT_RETRY_* 상수 참고). 재시도까지
//     모두 실패하거나 프로세스 자체가 죽으면, 다음 사이클(또는 운영자가 재기동한
//     데몬)이 같은 expectedRoot로 prepare를 재계산해 commit을 마저 진행한다(IdP가
//     게시된 상태만 서빙하므로 재계산 결과는 같고, push도 같은 root 재게시라
//     해롭지 않다).
// 정상 종료(SIGINT/SIGTERM) 처리는 진행 중인 사이클이 위 커밋 재시도까지 포함해
// 자연스럽게 끝나도록 기다렸다가 다음 사이클을 시작하지 않는 것으로 이뤄진다 —
// 재시도 도중 종료 신호를 받아도 이번 사이클 자체를 강제로 끊지는 않는다(그러면
// 전면 장애 구간을 연 채로 프로세스가 끝나 버린다).
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

  // push_revocation_root.cjs와 동일하게 중복 게시 가드는 두지 않는다. grace window가
  // 없어진 뒤로 같은 root 재게시는 heartbeat로서의 의미조차 없지만(latestRoot 값이
  // 안 바뀌니 무효화도 없음), 데몬이 매 주기 같은 root를 밀어도 해롭지 않으므로 굳이
  // 막지 않는다.
  const tx = await registry.pushRoot(rootHex);
  const receipt = await tx.wait();
  console.log(`2/3 pushRoot: ${rootHex} (block ${receipt.blockNumber}, tx ${receipt.hash})`);

  // 3) commit — push가 확정된 뒤에만 IdP를 전진시킨다.
  //
  // 여기서부터 commit이 성공할 때까지는 전면 장애 구간이다(파일 상단 주석 참고):
  // 체인의 latestRoot는 이미 새 root인데 IdP는 옛 리프 집합을 서빙 중이라, 그 사이
  // 만들어지는 모든 witness의 root가 latestRoot와 어긋나 전원이 StaleRevocationRoot로
  // 막힌다. 그래서 commit 실패는 다음 사이클까지 기다리지 않고 짧은 간격으로 즉시
  // 재시도해 이 창을 좁힌다.
  let committed;
  let commitErr = null;
  for (let attempt = 0; attempt <= COMMIT_RETRY_ATTEMPTS; attempt++) {
    try {
      committed = await callIdPAdmin(idpBaseUrl, adminSecret, "/idp/publish/commit", {
        root: String(expectedRoot),
      });
      commitErr = null;
      break;
    } catch (err) {
      commitErr = err;
      if (attempt < COMMIT_RETRY_ATTEMPTS) {
        console.error(
          `[sweep] commit 실패 (시도 ${attempt + 1}/${COMMIT_RETRY_ATTEMPTS + 1}): ${err.message}. ` +
          `${COMMIT_RETRY_DELAY_MS}ms 후 재시도합니다 (체인은 이미 새 root로 전진했고 grace window가 ` +
          `없어, 이 창이 열려 있는 동안 정상 사용자의 트랜잭션까지 막힙니다).`
        );
        await sleepInterruptible(COMMIT_RETRY_DELAY_MS, () => false);
      }
    }
  }
  if (commitErr) {
    console.error(
      "\n" + "!".repeat(70) + "\n" +
      `[sweep] 경고: pushRoot(${rootHex})는 성공했지만 commit이 ${COMMIT_RETRY_ATTEMPTS + 1}번 시도 ` +
      "모두 실패했습니다. 체인의 latestRoot는 이미 전진했는데 IdP는 옛 리프 집합을 서빙 중이라, " +
      "이 상태가 이어지는 동안 폐기와 무관한 사용자를 포함해 전원의 /submitTransaction이 " +
      "StaleRevocationRoot로 막힙니다. 운영자 확인이 필요합니다.\n" +
      "!".repeat(70) + "\n"
    );
    throw commitErr;
  }
  console.log(
    `3/3 commit: published root=${committed.root}, leaves=${committed.leafCount}, ` +
    `pending=${committed.pendingCount}`
  );

  // commit은 상태 저장에 실패해도 200을 돌려주고 persistenceWarning을 싣는다(트리 전진은
  // append-only라 되돌릴 수 없고 재시도도 불가능하므로 5xx를 낼 수 없다 — custom_idp.js
  // 참고). 그걸 읽지 않으면 저장 실패가 "3/3 commit 성공"으로 보고되고 연속 실패
  // 카운터까지 리셋돼, IdP가 재시작하는 순간 전원이 StaleRevocationRoot로 막힌다.
  if (committed.persistenceWarning) {
    console.error(
      "\n" + "!".repeat(70) + "\n" +
      `[sweep] 경고: commit은 성공했지만 IdP가 상태를 저장하지 못했습니다.\n` +
      `        ${committed.persistenceWarning}\n` +
      "        지금은 정상 동작하지만 IdP를 재시작하면 커밋 이전 root를 서빙하게 되고, " +
      "체인에는 새 root가 있으므로 전원의 트랜잭션이 막힙니다. 상태 파일을 복구하기 전에는 " +
      "IdP를 재시작하지 마십시오.\n" +
      "!".repeat(70) + "\n"
    );
    const err = new Error(`commit succeeded but the IdP could not persist its state: ${committed.persistenceWarning}`);
    err.persistenceWarning = true;
    throw err;
  }

  if (String(committed.root) !== String(expectedRoot)) {
    throw new Error(
      `commit이 반영한 root(${committed.root})가 게시한 root(${expectedRoot})와 다릅니다. ` +
      `IdP 상태와 온체인 root가 어긋났습니다.`
    );
  }
  console.log("Published revocation root:", rootHex);
}

// grace window와 K개 순환 버퍼가 사라지면서, "간격이 만료 상한에 비해 안전한가"라는
// 질문 자체가 사라졌다 — 이제 root는 시간이 지나도 만료되지 않으므로, 간격이 아무리
// 길어도(심지어 데몬이 죽어도) 정상 사용자가 막히는 일은 생기지 않는다. 대신 간격은
// 온전히 "폐기가 실제로 반영되기까지 걸리는 시간"으로 의미가 바뀌었다. 그래서 기동을
// 막는 가드는 없애고, 그 지연을 운영자가 알 수 있도록 기동 시 로그로만 알린다.
function announceRevocationDelay(intervalSeconds) {
  console.log(
    `[sweep] 데몬 모드: 대기 중인 폐기는 다음 게시 주기(최대 약 ${intervalSeconds}초) 뒤에 ` +
    "반영됩니다. grace window가 없으므로 간격을 늘려도 정상 사용자의 트랜잭션이 막히는 " +
    "일은 없습니다 — 다만 데몬이 멈추면 마지막으로 게시된 root가 계속 유효해 모두 동작은 " +
    "하되, 대기 중인 폐기가 조용히 효력을 잃습니다(fail-open). 데몬 생존 감시는 운영자 " +
    "책임입니다."
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
//
// grace window가 사라지면서 실패 양식이 뒤집혔다(fail-closed -> fail-open). 예전에는
// 데몬이 멈추면 게시된 root가 GRACE_BLOCKS 뒤 만료돼 전원이 막혔다 — 실패가 시끄럽게
// 드러나는 fail-closed였다. 이제는 마지막으로 게시된 root가 latestRoot로 계속 남아
// 유효하므로, 데몬이 죽어도 기존 사용자는 계속 동작한다. 다만 대기 중인 폐기가 조용히
// 게시되지 않은 채 쌓이기만 한다 — 실패가 드러나지 않는 fail-open이다. 그래서 사이클
// 실패를 catch해서 로그만 남기고 다음 주기에 재시도하는 구조 자체는(사용자를 막지
// 않는다는 점에서) 여전히 무방하지만, 데몬이 살아있는지 감시할 책임이 전적으로
// 운영자에게 넘어갔다는 뜻이기도 하다. 그래서 실패가 연속되면(=진짜 문제일 가능성이
// 높음) 조용히 넘어가지 않고 눈에 띄는 경고를 반복 출력해 그 감시를 돕는다.
async function runLoop(ctx, intervalSeconds, failureAlertThreshold) {
  let shuttingDown = false;

  const onSignal = (sig) => {
    if (shuttingDown) {
      console.log(`[sweep] ${sig} 재수신 — 즉시 종료합니다.`);
      process.exit(1);
    }
    shuttingDown = true;
    console.log(
      `[sweep] ${sig} 수신 — 진행 중인 사이클(커밋 재시도 포함)을 마치고 종료합니다. ` +
      `(prepare~push 전이면 아무 변화 없이 끝난다. push~commit 사이는 grace window가 ` +
      `없어 전면 장애 구간이므로 강제로 끊지 않고 재시도까지 마치기를 기다린다 — 강제 ` +
      `종료하면 그 장애 상태가 다음 데몬 기동까지 그대로 남는다. 재신호 시 즉시 종료.)`
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
          `[sweep] 경고: 연속 ${consecutiveFailures}회 실패. grace window가 없어 정상 사용자는 ` +
          "계속 동작하지만(fail-open), 대기 중인 폐기가 게시되지 않은 채 계속 쌓이고 " +
          "있습니다. 운영자 확인이 필요합니다.\n" +
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
    // 단발 모드에도 같은 보호가 필요하다. 위 주석이 설명하는 "push~commit 사이는 전면
    // 장애 구간이라 강제로 끊으면 안 된다"는 성질은 데몬 모드에만 있는 게 아닌데,
    // 시그널 핸들러가 runLoop 안에만 있어 기본 경로(단발)에는 아무 보호가 없었다.
    // Ctrl+C 한 번이 정확히 그 창에서 프로세스를 죽일 수 있었다(2026-09-04 리뷰).
    const onSignalOnce = (sig) => {
      console.log(
        `[sweep] ${sig} 수신 — 단발 사이클을 마치고 종료합니다. ` +
        `(push~commit 사이는 grace window가 없어 전면 장애 구간이므로 강제로 끊지 않는다. ` +
        `재신호 시 즉시 종료.)`
      );
      process.once("SIGINT", () => process.exit(1));
      process.once("SIGTERM", () => process.exit(1));
    };
    process.once("SIGINT", () => onSignalOnce("SIGINT"));
    process.once("SIGTERM", () => onSignalOnce("SIGTERM"));

    await runOneCycle(ctx);
    return;
  }

  const intervalSeconds = Number(intervalRaw);
  if (!Number.isFinite(intervalSeconds) || intervalSeconds <= 0) {
    throw new Error(`REVOCATION_SWEEP_INTERVAL_SECONDS는 양수(초)여야 합니다: ${intervalRaw}`);
  }

  announceRevocationDelay(intervalSeconds);

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
