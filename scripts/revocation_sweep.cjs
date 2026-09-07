const hre = require("hardhat");
const { getIdPSigner } = require("./revocation_idp.cjs");



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
const COMMIT_RETRY_DELAY_MS = 2000; // 재시도 사이 대기. push 이전이라 장애 구간은 아니다(위 주석 참고).

// 폐기 게시 한 사이클(batch publish). IdP에 대기 중인 폐기를 반영하고 만료된 리프를
// 정리한 다음 그 root를 온체인에 게시한다.
//
// 순서는 prepare(집합 동결) -> commit(IdP 전진, root 확정) -> pushRoot(온체인 게시)다.
// 게시할 root가 두 층의 상위 root를 합친 값이라 포레스트가 전진한 뒤에야 정해지기
// 때문이다(설계 문서 13.1절). v2 시절에는 prepare가 root를 예측할 수 있어 순서가
// prepare -> push -> commit이었다.
//
// 중단 지점(프로세스 kill, SIGINT 등)은 이제 **둘 다 안전하다.**
//   - prepare 이후 commit 이전에 중단 -> IdP·온체인 둘 다 아무 변화 없음. 다음 사이클이
//     처음부터 다시 prepare한다.
//   - commit 이후 push 이전에 중단 -> IdP가 앞서고 체인이 뒤처진다. 체인의 latestRoot는
//     아직 옛 root라, 그 root에 대한 witness를 이미 들고 있는 지갑은 그대로 동작한다.
//     새로 조회하는 지갑은 아직 게시되지 않은 root로 증명을 만들어 막히지만, 다음
//     사이클의 push가 같은 root를 올려 자동으로 수습된다. 유예 창이 인플라이트를 K블록
//     더 보호한다.
//
// v2 시절에는 후자가 push 후 commit 실패였고, 체인이 앞서 있어 그 사이 만들어지는 모든
// witness가 어긋나는 **전면 장애 구간**이었다. 순서를 뒤집으면서 그 구간이 사라졌다.
// commit 재시도(COMMIT_RETRY_*)는 그 창을 좁히려던 장치였는데, 이제는 회차를 흘려보내지
// 않으려는 용도로만 남는다.

// 정상 종료(SIGINT/SIGTERM) 처리는 진행 중인 사이클이 위 커밋 재시도까지 포함해
// 자연스럽게 끝나도록 기다렸다가 다음 사이클을 시작하지 않는 것으로 이뤄진다 —
// 재시도 도중 종료 신호를 받아도 이번 사이클 자체를 강제로 끊지는 않는다(그러면
// 전면 장애 구간을 연 채로 프로세스가 끝나 버린다).
async function runOneCycle(ctx) {
  const { idpBaseUrl, adminSecret, registry } = ctx;
  // lib/은 ESM이라 CJS 스크립트에서 동적 import로 가져온다.
  const { buildContractUpdates } = await import("../lib/transition_proof.js");

  // 1) prepare — 이번 회차에 반영할 집합을 동결하고 회차 토큰을 받는다. IdP 게시 상태는
  //    그대로다. v2 시절과 달리 여기서 root를 예측하지 않는다(설계 문서 13.1절).
  const prepared = await callIdPAdmin(idpBaseUrl, adminSecret, "/idp/publish/prepare");
  const roundToken = prepared.roundToken;
  if (!roundToken) {
    throw new Error(`/idp/publish/prepare 응답에 roundToken이 없습니다 (${idpBaseUrl})`);
  }
  console.log(
    `1/3 prepare: added=${prepared.added}, expiredPublished=${prepared.expiredPublished}, ` +
    `leaves=${prepared.leafCount}, pending=${prepared.pendingCount}`
  );
  console.log(`    currentRoot=${prepared.currentRoot}`);

  // 2) commit — IdP 포레스트를 전진시킨다. 게시할 root는 여기서 정해진다.
  //
  // 실패 시 짧은 간격으로 재시도한다. v2 시절 이 재시도는 **전면 장애 구간을 좁히려는**
  // 것이었다(push가 먼저라 체인이 앞서 있었다). v3에서는 아직 push 전이라 실패해도
  // 체인·IdP 둘 다 그대로이므로 장애 구간이 아니다 — 그래도 회차를 흘려보내지 않으려고
  // 재시도는 유지한다.
  let committed;
  let commitErr = null;
  for (let attempt = 0; attempt <= COMMIT_RETRY_ATTEMPTS; attempt++) {
    try {
      committed = await callIdPAdmin(idpBaseUrl, adminSecret, "/idp/publish/commit", { roundToken });
      commitErr = null;
      break;
    } catch (err) {
      commitErr = err;
      if (attempt < COMMIT_RETRY_ATTEMPTS) {
        console.error(`[sweep] commit 실패 (시도 ${attempt + 1}/${COMMIT_RETRY_ATTEMPTS + 1}): ${err.message}`);
        await sleepInterruptible(COMMIT_RETRY_DELAY_MS, () => false);
      }
    }
  }
  if (commitErr) throw commitErr;
  console.log(
    `2/3 commit: root=${committed.root}, leaves=${committed.leafCount}, pending=${committed.pendingCount}`
  );

  // commit은 상태 저장에 실패해도 200을 돌려주고 persistenceWarning을 싣는다(포레스트
  // 전진은 이미 끝났고 preparedPublish도 비워져 재시도가 불가능하므로 5xx를 낼 수 없다 —
  // custom_idp.js 참고). 그때는 **push하지 않고 중단한다.** 저장되지 않은 root를 온체인에
  // 올리면 IdP 재시작 후 옛 root를 서빙해 전원이 StaleRevocationRoot로 막힌다.
  if (committed.persistenceWarning) {
    console.error(
      "\n" + "!".repeat(70) + "\n" +
      `[sweep] 경고: commit은 성공했지만 IdP가 상태를 저장하지 못했습니다.\n` +
      `        ${committed.persistenceWarning}\n` +
      "        이 root를 push하지 않고 중단합니다. 상태 파일을 복구하기 전에는 IdP를 " +
      "재시작하지 마십시오.\n" +
      "!".repeat(70) + "\n"
    );
    const err = new Error(`commit succeeded but the IdP could not persist its state: ${committed.persistenceWarning}`);
    err.persistenceWarning = true;
    throw err;
  }

  // 3) pushUpdates — commit이 기록한 전이에 증명을 붙여 올린다.
  //
  // 여기서 root를 올리지 않는다는 것이 V4의 요점이다. 컨트랙트가 현재 root에서 시작해
  // 검증된 전이만 접어 올려 새 root를 **유도한다**(설계 문서 13.2절). 그래서 롤백도,
  // 아무도 witness를 만들 수 없는 쓰레기 root도 올릴 방법이 없다.
  const descriptors = committed.updates ?? [];
  if (descriptors.length === 0) {
    // 넣을 것도 회수할 것도 없었던 회차다. 올릴 전이가 없으므로 트랜잭션을 만들지 않는다
    // (V3에서 같은 root 재게시를 건너뛰던 것과 같은 자리다).
    console.log("3/3 pushUpdates: skip — 이번 회차에 바뀐 서브트리가 없다");
    return;
  }

  const updates = await buildContractUpdates(descriptors, (n, total, kind) => {
    if (kind === "insert") console.log(`    증명 생성 ${n}/${total} (${kind})`);
  });

  const tx = await registry.pushUpdates(updates);
  const rc = await tx.wait();
  console.log(
    `3/3 pushUpdates: ${updates.length}건 (block ${rc.blockNumber}, tx ${rc.hash}, gas ${rc.gasUsed})`
  );

  // 컨트랙트가 유도한 root가 IdP가 독립적으로 계산한 root와 같아야 한다. 다르면 전이
  // 서술이 실제 포레스트 변경과 어긋났다는 뜻이고, 그대로 두면 지갑이 만드는 witness가
  // 체인과 맞지 않는다.
  const onchain = await registry.latestRoot();
  if (String(onchain).toLowerCase() !== String(committed.root).toLowerCase()) {
    throw new Error(
      `컨트랙트가 유도한 root(${onchain})가 IdP의 root(${committed.root})와 다릅니다. ` +
      `전이 서술이 실제 변경과 어긋났습니다 — 운영자 확인이 필요합니다.`
    );
  }

  // 반영이 확인됐으니 IdP의 백로그에서 지운다. 이 호출이 실패하거나 생략되면 다음
  // 사이클이 같은 전이를 다시 올리려다 SubtreeMismatch로 막힌다 — 그래서 실패를 삼키지
  // 않는다. 반대로 push는 됐는데 ack만 실패한 경우는 다음 사이클에서 드러난다.
  const acked = await callIdPAdmin(idpBaseUrl, adminSecret, "/idp/publish/ack", {
    count: updates.length,
  });
  if (acked.persistenceWarning) {
    console.error(`[sweep] 경고: ack이 저장되지 않았습니다 — ${acked.persistenceWarning}`);
  }
  console.log(`    ack: ${acked.acknowledged}건 확인, 백로그 ${acked.pending}건 남음`);
  console.log("Published revocation root:", onchain);
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
  // v3에서는 레지스트리 컨트랙트가 다르다(유예 창 + isAcceptableRoot).
  const registry = await hre.ethers.getContractAt(
    "RevocationRegistryV4",
    registryAddress,
    idpSigner,
  );

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

// 명시적으로 종료한다. 13.2 전환으로 이 스크립트가 Groth16 증명을 만들게 되면서
// snarkjs가 워커 스레드를 남기고, 그러면 단발 모드가 일을 다 끝내고도 프로세스가 살아
// 있는다(cron으로 돌리면 영영 안 끝난다). 데몬 모드에서는 runLoop가 종료 신호로 빠져나온
// 뒤에 여기에 닿는다.
main()
  .then(() => process.exit(0))
  .catch((e) => { console.error(e); process.exit(1); });
