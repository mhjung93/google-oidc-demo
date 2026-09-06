import 'dotenv/config';
import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import cors from 'cors';
import mcl from 'mcl-wasm';
import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import * as snarkjs from 'snarkjs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { recoverAddress, keccak256, AbiCoder } from 'ethers';
import { leafValue, TAG_SESSION, TAG_ACCOUNT } from './lib/imt.js';

import { createIdPRevocationV3, LAYER_SESSION, LAYER_ACCOUNT } from './lib/idp_revocation_v3.js';
import { SESSION_SHARD_COUNT, ACCOUNT_SHARD_COUNT } from './lib/imt_v3.js';

const app = express();
// 기본값은 데모 구성 그대로다. 환경변수는 테스트가 **격리된 IdP 인스턴스**를 띄우기
// 위한 것이다 — 다른 포트, 다른 상태·키 파일을 쓰면 개발자가 띄워 둔 :4000 인스턴스와
// 그 폐기 트리를 건드리지 않고 실패 경로까지 실제로 돌려볼 수 있다.
const PORT = Number(process.env.CUSTOM_IDP_PORT) || 4000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// VKey 로드
const vkeyAridI = JSON.parse(fs.readFileSync('build/mode2/pi_arid_i_vkey.json', 'utf8'));

// 폐기 트리. 아래 상태들은 idp_state.json에 영속화되어 재시작을 넘어 살아남는다
// (issuanceLog/auidILog/users[*].lastAuid도 함께 — 파일 하단의 영속화 절 참고).
//
// == 게시된 상태와 대기 상태의 분리 (배칭) ==
// v3 이중 트리(revocationV3)가 '마지막으로 온체인에 게시된' 폐기 상태의 유일한 진실이다
// (13.1절에서 v2를 걷어냈다). /idp/revocation_state_v3가 이것만 서빙한다. 폐기 요청은 즉시
// 트리에 들어가지 않고 pendingAdds에 쌓였다가 /idp/publish/prepare + /idp/publish/commit
// 때 한꺼번에 반영된다.
//
// 왜 즉시 반영하면 안 되는가: 지갑은 /idp/revocation_state_v3로 자기 샤드를 재구성해
// witness를 만드는데, 그 root가 RevocationRegistryV3에 게시돼 있지 않으면 온체인
// execute()가 StaleRevocationRoot로 revert한다. 폐기 즉시 IdP 상태만 전진하면
// 게시 전까지 '정상 사용자 전원'이 막힌다. 게시될 때까지 옛(=게시된) 상태를 계속
// 서빙하면 그 장애 창이 사라지고, 폐기 효력 지연은 게시 주기만큼으로 유계가 된다.
// 접수됐지만 아직 게시되지 않은 폐기 리프(leaf 문자열).
const pendingAdds = new Set();
// prepare가 계산해 둔 다음 게시 후보. commit이 재계산 없이 그대로 소비한다.
//   { root: string, leaves: string[], blockHeight: bigint }
//
// 이 값은 의도적으로 영속화하지 않는다. prepare와 commit 사이에만 존재하는 일시적
// 상태이고, 그 사이에 재시작이 일어났다면 온체인 게시가 실제로 성사됐는지 알 수 없다.
// 되살려서 옛 후보를 commit하는 것보다, 운영자가 prepare를 다시 불러 현재 상태로부터
// 후보를 새로 계산하게 하는 편이 안전하다(재시작 후 commit은 409를 받는다).
let preparedPublish = null;
// 리프별 만료 블록. lib/imt_v3.js는 트리만 알아야 하므로, 만료 메타데이터(leaf 문자열 ->
// expiryBlock BigInt)는 게시 상태와 나란히 IdP가 따로 관리한다. 게시분과 대기분을
// 함께 담는다.
const leafExpiry = new Map();

// ============================================================================
// 폐기 상태 — v3(이중 트리)가 유일한 진실이다
//
// 2026-09-07에 v2를 게시 프로토콜에서 완전히 떼어냈다(설계 문서 13.1절). 그전까지 v2는
// 죽은 코드가 아니라 뼈대였다: 대기열 중복제거, 게시된 집합의 출처, prepare/commit의 root
// 합의가 전부 v2 위에 있었다. 셋을 **한 번에** 옮겼다 — 나눠서 옮기면 v2가 "먹이를 못 받는
// 거울"이 되어 재폐기된 리프가 영영 들어가지 못한다(13.1절에 실측과 함께 기록해 뒀다).
//
// 함께 사라진 것과 그 이유:
//   - epoch/seq/변경 로그(증분 동기화) — v3에서는 지갑이 자기 샤드 하나(최대 256~1,024
//     리프)만 받으므로 캐시도 증분도 필요 없다. 캐시가 없으면 캐시 일관성 결함도 없다.
//   - 용량 임계치와 강제 재기준화(80%/95%/하드 리밋) — v3에는 전역 용량이 없다. 세션 층은
//     만료 축이 샤드 인덱스에 들어 있어 회수가 샤드 리셋 한 번이고(설계 문서 3.2절),
//     계정 층은 샤드 단위 재기준화로 회수한다. 전 지갑 재다운로드를 부르는 전역
//     재기준화라는 조작 자체가 없어졌다.
//   - /idp/revocation_state_v2, /idp/rebaseline_v2, /idp/v3/rebuild_from_v2 —
//     마지막 것은 v2를 원본 삼아 v3를 되찾는 장치였으므로 원본과 함께 사라진다.
//   - prepare의 root 예측 — v3 게시 순서는 prepare -> commit -> push라 게시할 root는
//     commit이 전진한 **뒤에야** 정해진다. 회차 합의는 root 대신 회차 토큰으로 한다.
//
// lib/imt_v2.js는 그대로 쓴다. **v3의 서브트리 엔진이 바로 그것이다** — lib/imt_v3.js가
// 샤드마다 createIMTv2(depth)를 하나씩 만든다. 사라진 것은 "깊이 20 트리 하나를 IdP가
// 통째로 들고 서빙하던 배선"이지 라이브러리가 아니다. 같은 라이브러리가 논문이 인용하는
// "깊이 20, 32,000리프 재구성 24,752 ms" 기준선도 낸다(scripts/bench_imt_v2.mjs).
// ============================================================================
let revocationV3 = await createIdPRevocationV3();

// 현재 게시된 폐기 리프(leaf 문자열) 집합 = v3 두 층의 합집합.
//
// 같은 이름이던 v2 판과 **집합이 다르다**: v2는 append-only라 만료 리프를 재기준화 전까지
// 들고 있었고 v3는 만료를 실제로 회수한다. 전환 전 운영 IdP에서 한 회차 동안 병행 대조해
// 차이가 전부 만료로 설명됨을 확인했다(설계 문서 13.1절: v2 9 / v3 1, 차이 8건 전부 만료).
function publishedLeaves() {
  return [...revocationV3.publishedLeafSet()];
}

// custom_idp.js는 지금까지 체인 접근이 전혀 없었다. 만료 판정에 현재 블록이
// 필요해서 server.js:27,238과 동일한 관례로 eth_blockNumber를 조회한다.
const MODE2_ETH_RPC_URL = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';

async function getCurrentBlockHeight() {
  const response = await fetch(MODE2_ETH_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_blockNumber',
      params: [],
    }),
  });

  if (!response.ok) {
    throw new Error(`eth_blockNumber RPC failed with status ${response.status}`);
  }

  const data = await response.json();
  if (data.error || typeof data.result !== 'string') {
    // 조용히 0이나 기본값으로 떨어지면 만료 판정이 전부 틀어지므로(모든 크레덴셜이
    // 즉시 만료로 보이거나, 반대로 아무것도 만료되지 않는 것으로 보임) 명확히 던진다.
    throw new Error(data.error?.message || 'eth_blockNumber RPC returned no result');
  }

  return BigInt(data.result);
}

// wallet_agent.js의 TOKEN_VALIDITY_SECONDS/ETHEREUM_SLOT_SECONDS 관례를 그대로 따라
// 크레덴셜 수명(블록 수)을 유도한다: ceil(3600 / 12) = 300. 숫자 300을 그대로
// 박지 않는다 — 두 상수 중 하나만 바뀌어도 계산이 따라오게 하기 위함.
const TOKEN_VALIDITY_SECONDS = 3600n;
const ETHEREUM_SLOT_SECONDS = 12n;
const CREDENTIAL_LIFETIME_BLOCKS = (TOKEN_VALIDITY_SECONDS + ETHEREUM_SLOT_SECONDS - 1n) / ETHEREUM_SLOT_SECONDS;
// 지갑이 max_height를 계산한 시점과 IdP가 현재 블록을 읽는 시점 사이의 간격을 흡수한다.
// 같은 노드를 보면 IdP 쪽이 더 나중이라(≥) 여유가 필요 없지만, 노드가 다르거나 재구성이
// 있으면 지갑이 몇 블록 앞설 수 있다.
const MAX_HEIGHT_SLACK_BLOCKS = 32n;

// 크레덴셜 유효기간의 상한을 강제한다.
//
// max_height는 지갑이 정하고 IdP는 지금까지 "증명 신호와 일치하는가"만 봤다. 그런데
// 계정 폐기 리프의 만료는 접수 시점 + CREDENTIAL_LIFETIME_BLOCKS로 고정되므로, 수정된
// 지갑이 훨씬 먼 max_height를 받아두면 폐기가 무력화된다: 폐기 리프는 300블록 뒤
// 만료로 회수되는데 크레덴셜은 그보다 오래 살아, 그 사이 계정 비멤버십을 다시 통과한다.
// PPIDWallet.execute의 block.number > max_height 만료 검사도 사실상 무한이 된다.
// (2026-09-04 리뷰. tests/test_max_height_bound.js가 이 불변식을 고정한다.)
async function assertMaxHeightWithinBound(maxHeightSignal) {
  const maxHeight = BigInt(maxHeightSignal);
  const currentBlock = await getCurrentBlockHeight();
  const limit = currentBlock + CREDENTIAL_LIFETIME_BLOCKS + MAX_HEIGHT_SLACK_BLOCKS;
  if (maxHeight > limit) {
    throw new Error(
      `max_height ${maxHeight} exceeds the allowed credential lifetime ` +
        `(current block ${currentBlock} + ${CREDENTIAL_LIFETIME_BLOCKS} + ${MAX_HEIGHT_SLACK_BLOCKS} slack = ${limit}). ` +
        'Revocation assumes credentials expire within that window.',
    );
  }
  if (maxHeight <= currentBlock) {
    throw new Error(`max_height ${maxHeight} is already expired at block ${currentBlock}`);
  }
}

function now() { return Date.now(); }
function cursor() { return { last: now() }; }
function ms(c) {
  const t = now();
  const delta = t - c.last;
  c.last = t;
  return `${delta.toFixed(0)} ms`;
}

app.use(cors());
app.use(bodyParser.json());
app.use('/idp', express.static(path.join(__dirname, 'idp')));
app.use(session({
  name: 'idp_sid', // server.js도 127.0.0.1에서 돌아서, 기본 이름(connect.sid)을 쓰면
                   // 브라우저 쿠키 잡(포트 구분 안 함)이 서로 덮어써버린다.
  secret: 'custom-idp-secret',
  resave: false,
  saveUninitialized: true
}));

app.get('/idp', (req, res) => {
  res.sendFile(path.join(__dirname, 'idp', 'index.html'));
});

app.get('/idp/', (req, res) => {
  res.sendFile(path.join(__dirname, 'idp', 'index.html'));
});

// --- PS Signature Implementation ---
let psParams = {
  g1: null,
  g2: null,
};

let idpKeys = {
  x: null,
  y: [], // For multiple attributes: [domain, arid_i, auid_i, r_token, max_height, chain_id]
  pk: {
    X: null,
    Y: []
  }
};

// EdDSA-Poseidon 키쌍 — RP_REG에 쓰는 PS 키(idpKeys)와는 완전히 별개. auth token(IDP_TOKEN)
// 서명 전용.
let eddsa = null;
let poseidon = null;
let idpEdDSAKeys = {
  prv: null, // raw bytes (Buffer) — circomlibjs signPoseidon()이 요구하는 형식, mcl.Fr 아님
  pub: null, // [x, y], F-internal representation
};

// --- IdP 장기 키 영속화 ---
//
// 예전에는 기동할 때마다 EdDSA-Poseidon 키와 PS 키를 새로 뽑았다. 그래서 IdP를 재시작할
// 때마다 server.js가 캐싱한 PS 공개키, wallet_agent.js가 캐싱한 pk_IdP, 그리고
// PPIDWalletFactory에 불변으로 새겨진 신뢰 IdP 키가 한꺼번에 어긋나면서 factory
// 재배포까지 이어지는 전체 복구 체인을 돌아야 했다. 키를 파일에 보관해 그 체인을 없앤다.
//
// 저장하는 것은 비밀값뿐이다. 공개키는 매 기동 때 비밀값에서 다시 유도한다:
//   - EdDSA-Poseidon: 개인키 32바이트만 저장. 공개키는 eddsa.prv2pub(prv).
//   - PS: x와 y[0..5](mcl.Fr)만 저장. 공개키 X/Y[]는 mcl.mul(psParams.g2, ...).
// psParams.g1/g2는 hashAndMapToG1('gen1') / hashAndMapToG2('gen2')로 만드는 결정적
// 값이므로(서로 다른 프로세스에서 같은 값이 나오는 것을 확인함) 저장하지 않는다.
const IDP_KEY_FILE = process.env.IDP_KEY_FILE
  ? path.resolve(process.env.IDP_KEY_FILE)
  : path.join(__dirname, 'idp_keys.json');
const IDP_KEY_FILE_VERSION = 1;

// 개발용 강제 회전 스위치. 설정하면 기존 키 파일을 무시하고 새 키를 생성해 덮어쓴다.
// 회전 후에는 server.js 재시작 → PPIDWalletFactory 재배포 → wallet_agent.js 재시작이
// 필요하다(README.md 참고).
const IDP_ROTATE_KEYS = Boolean(process.env.IDP_ROTATE_KEYS);

// wallet_agent.js:361의 선례를 그대로 따른다 — 시크릿 파일은 소유자만 읽고 쓸 수 있게 한다.
//
// fs.writeFileSync(file, ...)는 내부적으로 open(O_TRUNC) 후 write()다. 그 사이에
// 프로세스가 죽으면(로그인 1회당 최소 2회 호출되므로 노출 창이 드물지 않다) 파일이
// 0바이트나 부분 JSON으로 남는다. 그 대신 같은 디렉터리 안의 임시 파일에 먼저 쓰고
// rename으로 교체한다 — POSIX에서 rename(2)은 원자적이라, 그 순간 관찰자는 옛 파일
// 전체 또는 새 파일 전체만 볼 수 있고 부분 상태는 절대 관측되지 않는다. 반드시 같은
// 디렉터리를 써야 한다: 파일시스템이 다르면 rename이 EXDEV로 실패하고 원자성이 깨진다.
function writeSecretFile(file, obj) {
  const dir = path.dirname(file);
  const tmpFile = path.join(dir, `.${path.basename(file)}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`);
  const data = JSON.stringify(obj, null, 2);

  // openSync에 mode를 줘서 파일이 존재하는 그 순간부터 0600이다 — writeFileSync 뒤에
  // 이어 chmod하는 방식은 그 사이에 더 열린 권한으로 잠깐 존재할 수 있다. 이 임시
  // 파일도 최종 파일과 동일한 시크릿을 담으므로 그 순간에도 보호돼야 한다.
  const fd = fs.openSync(tmpFile, 'w', 0o600);
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } catch (err) {
    fs.closeSync(fd);
    try { fs.unlinkSync(tmpFile); } catch { /* best-effort cleanup */ }
    throw err;
  }
  fs.closeSync(fd);

  try {
    fs.renameSync(tmpFile, file);
  } catch (err) {
    try { fs.unlinkSync(tmpFile); } catch { /* best-effort cleanup */ }
    throw err;
  }
}

// 손상된 키 파일을 만났을 때 조용히 새 키를 만들면, 운영자는 아무것도 모르는 채로
// server.js/wallet_agent.js의 캐시와 배포된 factory의 불변 키가 전부 어긋난 스택을
// 갖게 된다. 그래서 명확한 에러로 기동을 중단한다.
// detail에는 파일 '내용'을 절대 넣지 않는다 — 이 파일은 IdP 개인키다.
function keyFileError(detail) {
  return new Error(
    `[CustomIdP] IdP key file ${IDP_KEY_FILE} is unusable (${detail}). ` +
    'Refusing to silently generate new keys: that would leave the cached public keys in ' +
    'server.js / wallet_agent.js and the immutable IdP key baked into the deployed ' +
    'PPIDWalletFactory all pointing at a key that no longer exists. ' +
    'To rotate deliberately, start with IDP_ROTATE_KEYS=1 and then restart server.js, ' +
    'redeploy PPIDWalletFactory, and restart wallet_agent.js.',
  );
}

const FR_HEX_RE = /^[0-9a-f]+$/;

// mcl.Fr의 직렬화는 getStr(16) / setStr(hex, 16)이다. 무작위 2000개와 0/1/작은 값에서
// 왕복이 정확함을 실측으로 확인했다. setStr은 잘못된 16진수와 군 위수 이상의 값에는
// throw하지만 '-1' 같은 부호 있는 입력은 조용히 받아 전혀 다른 값이 되므로, setStr에
// 넘기기 전에 문자열 형식을 직접 검사한다.
function frFromHex(hex, label) {
  if (typeof hex !== 'string' || !FR_HEX_RE.test(hex)) {
    throw keyFileError(`${label} is not a lowercase hex string`);
  }
  const fr = new mcl.Fr();
  try {
    fr.setStr(hex, 16);
  } catch {
    throw keyFileError(`${label} is not a valid field element`);
  }
  // 이 파일은 항상 getStr(16)이 만든 정규 형식으로 쓰인다. 왕복이 어긋나면 변조·손상이다.
  if (fr.getStr(16) !== hex) {
    throw keyFileError(`${label} is not in canonical form`);
  }
  return fr;
}

function generateKeyMaterial() {
  const x = new mcl.Fr();
  x.setByCSPRNG();
  const y = [];
  for (let i = 0; i < 6; i++) {
    const yi = new mcl.Fr();
    yi.setByCSPRNG();
    y.push(yi.getStr(16));
  }
  return {
    version: IDP_KEY_FILE_VERSION,
    eddsa: { prv: randomBytes(32).toString('hex') },
    ps: { x: x.getStr(16), y },
  };
}

// 파일이 없으면 null, 있으면 검증된 키 재료. 형식이 조금이라도 어긋나면 throw한다.
function readKeyMaterial() {
  if (!fs.existsSync(IDP_KEY_FILE)) return null;

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(IDP_KEY_FILE, 'utf8'));
  } catch {
    // JSON 파서의 원본 메시지에는 파일 내용 조각이 섞여 나오므로 그대로 쓰지 않는다.
    throw keyFileError('not valid JSON');
  }

  if (parsed?.version !== IDP_KEY_FILE_VERSION) throw keyFileError('unsupported version');
  if (typeof parsed?.eddsa?.prv !== 'string' || !/^[0-9a-f]{64}$/.test(parsed.eddsa.prv)) {
    throw keyFileError('eddsa.prv must be 32 bytes of lowercase hex');
  }
  if (typeof parsed?.ps?.x !== 'string') throw keyFileError('ps.x is missing');
  if (!Array.isArray(parsed?.ps?.y) || parsed.ps.y.length !== 6) {
    throw keyFileError('ps.y must be an array of 6 elements');
  }
  return parsed;
}

function applyKeyMaterial(material) {
  idpEdDSAKeys.prv = Buffer.from(material.eddsa.prv, 'hex');
  idpEdDSAKeys.pub = eddsa.prv2pub(idpEdDSAKeys.prv);

  idpKeys.x = frFromHex(material.ps.x, 'ps.x');
  idpKeys.y = material.ps.y.map((hex, i) => frFromHex(hex, `ps.y[${i}]`));
  // 공개키는 저장하지 않고 항상 비밀값에서 유도한다 (X = g2^x, Yi = g2^yi).
  idpKeys.pk.X = mcl.mul(psParams.g2, idpKeys.x);
  idpKeys.pk.Y = idpKeys.y.map((yi) => mcl.mul(psParams.g2, yi));
}

// PS와 EdDSA-Poseidon 키를 한 번에 초기화한다. 둘 다 같은 키 파일에서 나오므로
// 예전처럼 initPS()/initEdDSA()로 나눠 부르지 않는다.
async function initKeys() {
  await mcl.init(mcl.BN_SNARK1);
  eddsa = await buildEddsa();
  poseidon = await buildPoseidon();

  // 결정적 생성자 — 저장하지 않고 매 기동 때 동일하게 다시 만든다.
  psParams.g1 = mcl.hashAndMapToG1('gen1');
  psParams.g2 = mcl.hashAndMapToG2('gen2');

  const existing = IDP_ROTATE_KEYS ? null : readKeyMaterial();
  const material = existing ?? generateKeyMaterial();
  applyKeyMaterial(material);

  // 키 '내용'은 어떤 경로로도 출력하지 않는다. 로드했는지 생성했는지만 알린다.
  if (existing) {
    console.log(`[CustomIdP] Loaded existing IdP keys from ${IDP_KEY_FILE}`);
  } else {
    writeSecretFile(IDP_KEY_FILE, material);
    const why = IDP_ROTATE_KEYS ? 'IDP_ROTATE_KEYS was set' : 'no key file found';
    console.log(`[CustomIdP] Generated new IdP keys (${why}) and stored them in ${IDP_KEY_FILE}`);
    console.warn(
      '[CustomIdP] New keys invalidate cached public keys downstream. Restart server.js, ' +
      'redeploy PPIDWalletFactory, then restart wallet_agent.js with the new factory address.',
    );
  }
  console.log('[CustomIdP] PS + EdDSA-Poseidon signatures initialized');
}

function hashToFr(str) {
  const fr = new mcl.Fr();
  fr.setHashOf(str);
  return fr;
}

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// wallet_agent.js/client.js/server.js에 이미 있는 것과 동일한 구현 — 문자열/숫자를
// Poseidon이 받을 수 있는 필드 원소로 바꾼다. hashToFr()(mcl 전용)와는 호환 안 됨.
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function valueToField(value) {
  if (typeof value === 'bigint') return value % FIELD_PRIME;
  if (typeof value === 'number') return BigInt(value) % FIELD_PRIME;
  const str = String(value);
  if (str.startsWith('0x')) return BigInt(str) % FIELD_PRIME;
  if (/^[0-9]+$/.test(str)) return BigInt(str) % FIELD_PRIME;
  const bytes = new TextEncoder().encode(str);
  const hex = bytesToHex(bytes);
  return BigInt(`0x${hex || '0'}`) % FIELD_PRIME;
}

 /**
  * PS Multi-Message Sign
 * @param {Array<string>} messages - domain-separated message vector
  */
function psSign(messages) {
  const randomStr = randomBytes(32).toString('hex');
  const h = mcl.hashAndMapToG1(randomStr);

  // exponent = x + sum(yi * mi)
  let exponent = idpKeys.x.clone();

  for (let i = 0; i < messages.length; i++) {
    const mi = hashToFr(messages[i]);
    const yi_mi = mcl.mul(idpKeys.y[i], mi);
    exponent = mcl.add(exponent, yi_mi);
  }

  const sigma1 = h;
  const sigma2 = mcl.mul(h, exponent);

  return {
    sigma1: sigma1.getStr(16),
    sigma2: sigma2.getStr(16)
  };
}

// Mock Database (UID를 순수 숫자로 변경하여 ZKP와 일치시킴)
// disabled: 계정 층 차단(사람 차단). 크레덴셜 폐기 트리(가역, "이미 발급된 것" 회수)와
// 역할이 다르다 — disabled는 "앞으로 로그인 자체를 막는다"(docs/REVOCATION_FOLLOWUPS.md 0절).
const users = {
  'testuser': { password: 'password123', uid: '12345', sub: '12345', lastAuid: null, disabled: false },
  'alice': { password: 'secret456', uid: '67890', sub: '67890', lastAuid: null, disabled: false }
};
const usedNonces = new Set();

// auid = Poseidon(uid, salt)는 pi_i의 6번째(마지막) public signal이고 계정마다 고정이다.
// 첫 성공 로그인에서 고정해두고 이후 달라지면 거부하는 것이 계정 폐기를 실제로 성립시킨다 —
// 폐기 리프가 Poseidon(TAG_ACCOUNT, auid)이므로, salt를 갈아끼운 지갑은 다른 auid를 제시해
// 자기 폐기를 그대로 통과해 버린다.
//
// 반드시 pi_i 증명 검증에 성공한 뒤에 호출할 것 — 그래야 위조 증명으로 저장값을 오염시킬 수 없다.
// 로그인 경로가 둘(/authorize/login, /sso_with_credentials)이므로 양쪽 모두에서 호출해야 한다.
function pinAuidToAccount(user, auidFromProof) {
  if (user.lastAuid !== null && String(user.lastAuid) !== String(auidFromProof)) {
    throw new Error('Wallet binding mismatch: this account is using a different salt than its last successful login');
  }
  user.lastAuid = auidFromProof;
  saveIdPState();
}

// B2 추적용 발급 로그: r_token -> { uid, maxHeight }.
// 단순 추적 로그가 아니라 보안 기능의 일부다 — /idp/revoke의 입구 검사가 "내가 발급한
// 세션인가"와 "이미 만료됐나"를 이걸로 판단한다. 그래서 idp_state.json에 영속화한다.
// 없으면 재시작 이전에 발급된 세션은 폐기 자체가 불가능해진다.
const issuanceLog = new Map();
// B2 추적용 발급 로그: auid_i -> uid. auid_i = ppid * rp_nonce는 세션마다 값이 바뀌지만,
// 어느 세션의 auid_i든 같은 ppid(=같은 계정)면 항상 같은 uid로 귀결되므로, RP가 그
// 지갑으로 가장 최근에 로그인했을 때의 auid_i만 들고 있어도 이 로그로 uid를 찾을 수
// 있다. issuanceLog와 같은 성격이라 함께 영속화한다.
const auidILog = new Map();

// --- IdP 폐기/발급 상태 영속화 ---
//
// 키(idp_keys.json)와 일부러 다른 파일로 나눈다. 키는 사실상 바뀌지 않고 상태는 폐기·
// 게시·로그인마다 바뀌므로, 자주 쓰는 파일이 개인키를 계속 다시 쓰게 만들 이유가 없다.
// 권한은 동일하게 0o600이다 — issuanceLog가 r_token -> uid 매핑이라 프라이버시 민감하다.
const IDP_STATE_FILE = process.env.IDP_STATE_FILE
  ? path.resolve(process.env.IDP_STATE_FILE)
  : path.join(__dirname, 'idp_state.json');
// v2: auidILog의 값이 uid 문자열 하나에서 issuanceLog와 같은 { uid, maxHeight } 객체로
// 바뀌었다 — 4-2번 만료 기반 축출이 auidILog에도 적용되려면 만료 정보가 필요해서다.
// v1 파일을 만나면 loadIdPState()가 자동으로 마이그레이션한다(아래 LEGACY_AUID_ILOG_MAX_HEIGHT
// 주석 참고) — 이 저장소의 실제 idp_state.json에 이미 게시된 폐기 7건, 발급 기록 5건이
// 들어있어(직접 확인함), "옛 파일은 거부"를 택하면 그걸 통째로 날리게 된다. auidILog는
// 보안 통제가 아니라 B2 추적 편의 기능(입장 검사는 issuanceLog가 전담)이라 마이그레이션의
// 유일한 대가가 "마이그레이션 이전 세션의 auid_i 추적이 다음 게시 주기까지만 가능"뿐이므로,
// 무손실 마이그레이션이 명확한 거부보다 낫다고 판단했다.
// v3: users에 disabled 플래그가 추가됐다(계정 층 차단, docs/REVOCATION_FOLLOWUPS.md 0절/1절
// 5번). v1·v2 파일에는 disabled 필드가 아예 없다 — loadIdPState()는 이를 명시적 거부가
// 아니라 마이그레이션으로 처리한다. 이 필드는 v1/v2보다도 더 명백히 무손실이다: 이 기능이
// 생기기 전에는 어떤 계정도 disabled로 표시될 수 없었으므로, 누락 = false는 추측이 아니라
// 그 시점의 실제 상태 그대로다.
// v4(Stage B): v1 폐기 트리(revocationTree)와 그 직렬화 필드(publishedRoot, revokedLeaves)를
// 제거하고 정석 IMT(v2)를 게시 상태의 유일한 진실로 승격했다. 이는 v1~v3와 달리 순수
// additive가 아닌 **진짜 파괴적 변경**이다(v1 필드가 사라진다). 그래서 이 시점에 스키마
// 버전을 4로 올린다 — Stage B는 회로/zkey/컨트랙트가 함께 바뀌는 되돌릴 수 없는 단계라
// (기존 zkey·CREATE2 주소 무효화), 되돌림 안전성을 위해 버전 bump를 미룰 이유가 이제 없다.
// v1/v2/v3 파일은 loadIdPState()가 v2 게시 집합으로 무손실 마이그레이션한다(아래 참고):
// v2Leaves가 있으면(v3, Stage A) 그대로 쓰고, 없으면 revokedLeaves 값으로 v2를 초기화한다.
// v6(13.1절): v2 폐기 트리와 그 직렬화 필드(v2Leaves/publishedRootV2/epochV2/seqV2)를 제거하고
// v3(이중 트리)를 게시 상태의 **유일한** 진실로 승격했다. v4에 이어 두 번째 파괴적 변경이다.
// v5 파일은 이미 v3 스냅샷을 담고 있어 무손실로 올라온다. v4 이하는 v3 스냅샷이 없고 리프
// 해시에서 층(session/account)을 되돌릴 수 없어 **마이그레이션이 불가능하다** — 빈 트리로
// 시작하면 온체인 root와 어긋나 폐기된 사용자가 아니라 전원의 트랜잭션이 막히므로, 조용히
// 시작하지 않고 거부한다.
const IDP_STATE_FILE_VERSION = 6;
const LEGACY_AUID_ILOG_MAX_HEIGHT = '0';

function stateFileError(detail) {
  return new Error(
    `[CustomIdP] IdP state file ${IDP_STATE_FILE} is unusable (${detail}). ` +
    'Refusing to start with a silently wrong revocation state: if the published root does not ' +
    'match what wallets rebuild from /idp/revocation_state_v3, every wallet transaction fails. ' +
    'Inspect the file to recover it. Do NOT delete it to "fix" this: the on-chain ' +
    'RevocationRegistry still holds the last root this IdP published, so starting from an empty ' +
    'tree makes the IdP serve a root that does not match it — every wallet\'s execute() then ' +
    'reverts with StaleRevocationRoot, blocking all users, not just revoked ones. Republishing to ' +
    'clear that mismatch would republish an empty tree, silently un-revoking every account and ' +
    'session this IdP had ever revoked (fail-open). If the file truly cannot be recovered, that ' +
    'republish-from-empty consequence must be a deliberate, informed decision, not the default ' +
    'unblock step.',
  );
}

const DECIMAL_RE = /^[0-9]+$/;

function assertDecimalString(value, label) {
  if (typeof value !== 'string' || !DECIMAL_RE.test(value)) {
    throw stateFileError(`${label} must be a decimal string`);
  }
  return value;
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// BigInt와 Map/Set은 JSON이 직접 담지 못한다. BigInt는 10진 문자열로, Map/Set은
// 객체/배열로 바꿔 저장하고 로드할 때 되돌린다.
function serializeIdPState() {
  return {
    version: IDP_STATE_FILE_VERSION,
    pendingAdds: [...pendingAdds],
    leafExpiry: Object.fromEntries([...leafExpiry].map(([k, v]) => [k, v.toString()])),
    issuanceLog: Object.fromEntries(
      [...issuanceLog].map(([k, v]) => [k, { uid: String(v.uid), maxHeight: String(v.maxHeight) }]),
    ),
    // v2: issuanceLog와 같은 { uid, maxHeight } 모양 — 4-2번 만료 기반 축출이
    // auidILog에도 적용되려면 만료 정보가 있어야 한다.
    auidILog: Object.fromEntries(
      [...auidILog].map(([k, v]) => [k, { uid: String(v.uid), maxHeight: String(v.maxHeight) }]),
    ),
    // users에서 영속화하는 것은 lastAuid와 disabled뿐이다. username/password/uid는
    // 소스에 있는 데모 상수라 저장할 이유가 없고, 저장하면 비밀번호가 파일로 새어나간다.
    lastAuid: Object.fromEntries(Object.entries(users).map(([name, u]) => [name, u.lastAuid])),
    // disabled는 보안 상태라 반드시 영속화해야 한다 — 안 그러면 재시작마다 차단이 풀린다.
    disabled: Object.fromEntries(Object.entries(users).map(([name, u]) => [name, Boolean(u.disabled)])),

    // === v3(이중 트리) — 게시 상태의 유일한 진실 ===
    // 샤드별 리프 배열은 물리 순서다(root가 삽입 순서에 의존한다).
    //
    // v6에서 사라진 것: v2Leaves/publishedRootV2/epochV2/seqV2. 마지막 둘은 지갑의 v2 증분
    // 동기화(since=<seq>)를 위한 것이었는데, v3에서는 지갑이 자기 샤드 하나만 통째로 받으므로
    // 증분 프로토콜 자체가 없다. 변경 로그는 그전부터 저장하지 않았다 — 상한 100,000항목이
    // 약 31MB고 saveIdPState가 **로그인마다** 불리므로 상태 파일의 압도적 지배항이었다.
    v3: revocationV3.serialize(),
  };
}

// 상태가 바뀔 때마다 호출한다.
// 이 함수 자체는 실패해도 던지지 않는다 — 실패 처리 정책(요청을 실패시킬지, 경고만
// 남기고 넘어갈지)은 호출자마다 다르다(/idp/revoke는 보안 조작이라 실패를 5xx로
// 돌려야 하고, 발급 경로는 로그인 자체를 막을 정도는 아니라고 판단해 응답에 경고
// 필드만 싣는다 — 아래 각 호출부 주석 참고). 그래서 성공 여부를 boolean으로 돌려주고,
// 무엇을 할지는 호출자가 결정한다. 다만 실패는 조용히 삼키지 않고 항상 에러 로그를
// 남긴다 — 호출자가 반환값을 무시하더라도(예: pinAuidToAccount) 운영자가 알 수 있게.
function saveIdPState() {
  try {
    writeSecretFile(IDP_STATE_FILE, serializeIdPState());
    return true;
  } catch (err) {
    console.error(
      `[IdP] FAILED to persist state to ${IDP_STATE_FILE}: ${err.message} — ` +
      'this change will be lost on restart',
    );
    return false;
  }
}

// 기동 시 1회. 파일이 없으면 빈 상태로 시작하고, 있으면 검증 후 복원한다.
async function loadIdPState() {
  if (!fs.existsSync(IDP_STATE_FILE)) {
    console.log(`[CustomIdP] No state file at ${IDP_STATE_FILE}; starting with empty revocation state`);
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(IDP_STATE_FILE, 'utf8'));
  } catch {
    throw stateFileError('not valid JSON');
  }

  // 마이그레이션 경로(모두 무손실):
  //   v1 -> v2: auidILog 값 모양(문자열 uid -> { uid, maxHeight }).
  //   v2 -> v3: users.disabled 추가(누락 = false).
  //   v3 -> v4(Stage B): v1 폐기 트리(revocationTree/publishedRoot/revokedLeaves) 제거,
  //             v2를 게시 상태의 유일한 진실로 승격.
  //   v4 -> v5: v3(이중 트리) 스냅샷 추가. v2와 나란히 저장했다.
  //   v5 -> v6(13.1절): v2 트리와 그 필드(v2Leaves/publishedRootV2/epochV2/seqV2) 제거,
  //             v3를 유일한 진실로 승격. v5 파일은 이미 v3 스냅샷을 담고 있어 무손실이다.
  // **v4 이하는 마이그레이션 경로가 없다** — v3 스냅샷이 없고 리프 해시에서 층을 되돌릴
  // 수 없어 게시 집합을 복원할 방법이 없다. 위에서 명확히 거부한다.
  // 완전히 낯선 버전도(마이그레이션 경로가 없으므로) 계속 명확히 거부한다.
  const fileVersion = parsed?.version;
  // v1 파일은 위에서 이미 거부된다(v3 스냅샷 없음). 남겨 두면 죽은 분기가 되므로 상수로 고정한다.
  const isLegacyAuidILog = false;
  // v3 파일에서 disabled가 생겼다. 이제 v5 이상만 읽으므로 항상 존재해야 한다.
  const hasDisabledField = fileVersion >= 3;
  if (![1, 2, 3, 4, 5, 6].includes(fileVersion)) {
    throw stateFileError('unsupported version');
  }
  // v5 미만은 v3(이중 트리) 스냅샷이 없다. 그 파일에서 v3를 복원할 방법이 없고(리프가
  // Poseidon 해시라 층을 되돌릴 수 없다), v3가 이제 게시의 유일한 진실이므로 빈 상태로
  // 시작하면 온체인 root와 어긋난다 — 폐기된 사용자가 아니라 **전원**이 막힌다.
  if (fileVersion < 5) {
    throw stateFileError(
      `version ${fileVersion} predates the v3 dual-tree snapshot and cannot be migrated: the ` +
      'published revocation set cannot be reconstructed from it (leaf hashes do not reveal the ' +
      'session/account layer). Starting from an empty tree would break every wallet, not just ' +
      'revoked ones. Restore a version 5 or later state file.',
    );
  }
  if (!Array.isArray(parsed.pendingAdds)) throw stateFileError('pendingAdds must be an array');
  for (const key of ['leafExpiry', 'issuanceLog', 'auidILog', 'lastAuid']) {
    if (!isPlainObject(parsed[key])) throw stateFileError(`${key} must be an object`);
  }
  if (hasDisabledField && !isPlainObject(parsed.disabled)) throw stateFileError('disabled must be an object');

  pendingAdds.clear();
  for (const [i, leafKey] of parsed.pendingAdds.entries()) {
    pendingAdds.add(assertDecimalString(leafKey, `pendingAdds[${i}]`));
  }

  leafExpiry.clear();
  for (const [leafKey, expiry] of Object.entries(parsed.leafExpiry)) {
    // 만료 블록은 저장할 때 BigInt -> 10진 문자열이었다. 되돌린다.
    leafExpiry.set(leafKey, BigInt(assertDecimalString(expiry, `leafExpiry[${leafKey}]`)));
  }

  issuanceLog.clear();
  for (const [rToken, entry] of Object.entries(parsed.issuanceLog)) {
    if (!isPlainObject(entry)) throw stateFileError(`issuanceLog[${rToken}] must be an object`);
    issuanceLog.set(rToken, {
      uid: String(entry.uid),
      maxHeight: assertDecimalString(String(entry.maxHeight), `issuanceLog[${rToken}].maxHeight`),
    });
  }

  // usedNonces(재전송 방지)는 그동안 재시작을 넘어 살아남지 못했다 — 예전엔 키가
  // 재시작마다 회전해 옛 r_token이 무의미했지만, 이제 키가 고정되므로 재시작 전
  // r_token을 재전송하면 같은 키 아래 유효한 두 번째 statement를 받을 수 있었다.
  // issuanceLog의 키(=발급된 모든 r_token)로 시드한다 — 두 발급 경로 모두 키를
  // String(...)/.toString()으로 만들어 형식이 동일한 10진 문자열이라 그대로 맞는다.
  // 이 시드는 issuanceLog가 저장에 실제로 성공했다는 전제에 전적으로 의존한다 —
  // 그래서 이 파일의 3번(저장 실패를 5xx로 드러내기)을 먼저 고쳤다.
  usedNonces.clear();
  for (const rToken of issuanceLog.keys()) usedNonces.add(rToken);

  auidILog.clear();
  for (const [auidI, rawEntry] of Object.entries(parsed.auidILog)) {
    if (isLegacyAuidILog) {
      // v1: 값이 uid 문자열뿐이라 만료를 모른다. "이미 만료된 것"으로 표시해 다음
      // 게시 주기(축출 로직, /idp/publish/commit)에 곧바로 정리 대상이 되게 한다.
      auidILog.set(auidI, { uid: String(rawEntry), maxHeight: LEGACY_AUID_ILOG_MAX_HEIGHT });
    } else {
      if (!isPlainObject(rawEntry)) throw stateFileError(`auidILog[${auidI}] must be an object`);
      auidILog.set(auidI, {
        uid: String(rawEntry.uid),
        maxHeight: assertDecimalString(String(rawEntry.maxHeight), `auidILog[${auidI}].maxHeight`),
      });
    }
  }

  // 소스에 존재하는 데모 계정에만 복원한다. 파일에 모르는 이름이 들어있어도 계정을
  // 새로 만들지 않는다 — 상태 파일이 계정 생성 경로가 되어서는 안 된다.
  for (const [name, lastAuid] of Object.entries(parsed.lastAuid)) {
    if (!Object.prototype.hasOwnProperty.call(users, name)) continue;
    users[name].lastAuid = lastAuid === null ? null : String(lastAuid);
  }

  // v3 파일에만 disabled가 있다. v1/v2 파일은 disabled 필드 자체가 없으므로 소스 기본값
  // (false)을 그대로 둔다 — 이 필드가 생기기 전에는 어떤 계정도 disabled일 수 없었다.
  if (hasDisabledField) {
    for (const [name, disabled] of Object.entries(parsed.disabled)) {
      if (!Object.prototype.hasOwnProperty.call(users, name)) continue;
      users[name].disabled = Boolean(disabled);
    }
  }

  // === v3(이중 트리) 복원 — 게시 상태의 유일한 진실 ===
  // v5부터 저장된다. 위에서 v5 미만을 이미 거부했으므로 여기서는 반드시 있어야 하고,
  // 없으면 "게시된 폐기 집합의 출처가 없다"는 뜻이라 조용히 빈 상태로 시작하지 않는다.
  if (!isPlainObject(parsed.v3)) {
    throw stateFileError('a version 5 or later state file must contain a v3 snapshot');
  }
  try {
    await revocationV3.restore(parsed.v3);
  } catch (err) {
    throw stateFileError(`v3 restore failed: ${err.message}`);
  }

  console.log(
    `[CustomIdP] Loaded state from ${IDP_STATE_FILE}: ${publishedLeaves().length} published leaves ` +
    `(combined root ${revocationV3.combinedRoot()}), ${pendingAdds.size} pending, ` +
    `${issuanceLog.size} issuance records, ${usedNonces.size} nonces seeded for replay protection`,
  );

  // 옛 버전 파일을 읽었다면 지금 인메모리 상태는 이미 최신(v4) 모양이다(직렬화가 항상
  // IDP_STATE_FILE_VERSION을 쓰므로). 지금 바로 커밋해두면 파일이 곧장 v4 모양이 되고
  // 마이그레이션이 실제로 성사됐음을 디스크에서 확인할 수 있다. v4 파일을 그대로 읽었을
  // 때는 다시 쓸 이유가 없다.
  if (fileVersion !== IDP_STATE_FILE_VERSION) {
    const changes = [];
    if (isLegacyAuidILog) {
      changes.push(
        'auidILog entries gained maxHeight tracking (pre-migration entries are marked ' +
        'already-expired and will be evicted on the next publish cycle — a convenience-feature ' +
        'side effect, not a security control; issuanceLog/usedNonces are unaffected)',
      );
    }
    if (!hasDisabledField) {
      changes.push('accounts gained a disabled flag, defaulted to false for every restored account');
    }
    changes.push(
      'removed the v1 revocation tree (publishedRoot/revokedLeaves); the v2 indexed Merkle tree ' +
      'is now the sole published-revocation source (the published set was carried over losslessly)',
    );
    console.warn(
      `[CustomIdP] Migrated state file from version ${fileVersion} to ${IDP_STATE_FILE_VERSION}: ` +
      `${changes.join('; ')}.`,
    );
    if (!saveIdPState()) {
      throw stateFileError(
        `migrated the in-memory state from version ${fileVersion} to version ${IDP_STATE_FILE_VERSION} ` +
        'but failed to persist the migrated file; refusing to run with an in-memory state that does ' +
        'not match what is on disk',
      );
    }
  }
}

await loadIdPState();
// 비밀번호 인증(/sso_with_credentials) 후 동의 클릭(/consent_result)까지 허용하는 최대 시간.
const PENDING_CONSENT_TTL_MS = 5 * 60 * 1000;

function summarizeValue(value) {
  if (value === undefined || value === null) return 'missing';
  const str = typeof value === 'string' ? value : JSON.stringify(value);
  return str.length > 80 ? `${str.slice(0, 80)}...` : str;
}

function assertDecimalSignals(signals, expectedLength, name) {
  if (!Array.isArray(signals) || signals.length !== expectedLength) {
    throw new Error(`${name} public signals must be an array of length ${expectedLength}`);
  }
  for (const signal of signals) {
    if (typeof signal !== 'string' || !/^[0-9]+$/.test(signal)) {
      throw new Error(`${name} public signals must be decimal strings`);
    }
  }
  return signals;
}

// 1. RP Registration
app.post('/register_rp', (req, res) => {
  const { rpName, callbackUrl, origin } = req.body;
  if (!origin) {
    return res.status(400).json({ error: 'origin is required for RP registration' });
  }
  // rid를 큰 숫자 스칼라(248비트 랜덤)로 발급 — pi_i 회로의 private input rid로 쓰인다.
  const rid = BigInt('0x' + randomBytes(31).toString('hex')).toString();

  // origin을 서명 대상에 포함시켜서, rid와 origin의 묶음 자체를 IdP가 보증한다.
  // 이게 없으면 RP FE(client.js)가 이 rid를 다른 origin의 것인 척 wallet에
  // 제출해도(다른 RP의 정상 발급 rid를 몰래 끼워 넣어도) wallet이 구분할 방법이
  // 없다 — origin이 서명 안에 있어야 wallet이 "이 rid, 진짜 내가 보고 있는
  // origin 거 맞아?"를 credential 하나만으로 검증할 수 있다.
  // EdDSA-Poseidon으로 서명(예전엔 PS 서명이었음) — wallet_agent.js가 로컬에서
  // 검증하는 용도 외에, pi_arid_i 회로 안에서 "이 rid/origin이 IdP가 발급한 진짜
  // credential에 묶여있다"를 rid/origin을 공개하지 않고 증명하는 데도 쓴다(같은
  // idpEdDSAKeys를 재사용 — IDP_TOKEN 서명과 별개 키를 새로 만들 필요 없음).
  const DOMAIN_RP_REG = valueToField('RP_REG');
  const rpRegMsg = poseidon([DOMAIN_RP_REG, valueToField(rid), valueToField(origin)]);
  const rpRegSig = eddsa.signPoseidon(idpEdDSAKeys.prv, rpRegMsg);

  const rpToken = {
    rpName,
    rid,
    origin,
    signature: {
      R8: [
        eddsa.F.toObject(rpRegSig.R8[0]).toString(),
        eddsa.F.toObject(rpRegSig.R8[1]).toString(),
      ],
      S: rpRegSig.S.toString(),
    },
    issuedAt: new Date().toISOString()
  };

  res.json(rpToken);
});

// ── PAR (RFC 9126) + Authorization Code + PKCE ── additive alongside the
// existing /register_rp, /sso_with_credentials, /consent_result flow. See
// docs/superpowers/specs/2026-07-24-idp-par-authorize-token-design.md.
const PAIRCT_CLIENT_ID = 'pairct-wallet';
const LOOPBACK_REDIRECT_URI_PATTERN = /^http:\/\/127\.0\.0\.1:\d+\/oidc\/callback$/;
// request_uri의 수명은 **사람이 로그인 폼을 채우고 동의를 누르기까지**를 덮어야 한다.
// 60초는 그 전체를 덮지 못해, 비밀번호까지 통과한 뒤 동의 시점에 레코드가 만료돼 로그인
// 전체가 날아갔다(2026-09-04 리뷰). 5분으로 늘린다 — 이 값은 "발급된 인가 코드"가 아니라
// "아직 인증도 안 된 요청"의 수명이라, 늘려도 공격 표면이 늘지 않는다(단일 사용이고,
// 동의는 로그인한 세션에만 묶인다). 인가 코드 TTL(60초)은 그대로 둔다.
const PAR_REQUEST_TTL_MS = 5 * 60 * 1000;
const AUTHORIZATION_CODE_TTL_MS = 60 * 1000;

// request_uri -> { redirect_uri, state, nonce, code_challenge,
// code_challenge_method, zkpProof, zkpPublicSignals, chain_id,
// requestBinding, expiresAt, [authenticatedUid, arid_i, auid_i, max_height,
// token_nonce, auid] }. Memory-only, same "intentional demo limitation" as
// issuanceLog/auidILog/usedNonces below.
const pushedRequests = new Map();
// code -> { redirect_uri, code_challenge, code_challenge_method, nonce,
// arid_i, auid_i, max_height, token_nonce, auid, chain_id, uid, expiresAt }.
const authorizationCodes = new Map();

function pruneExpired(map) {
  const now = Date.now();
  for (const [key, record] of map) {
    if (record.expiresAt <= now) map.delete(key);
  }
}

app.post('/par', async (req, res) => {
  pruneExpired(pushedRequests);
  const {
    client_id, redirect_uri, response_type,
    state, nonce, code_challenge, code_challenge_method,
    zkpProof, zkpPublicSignals, chain_id, requestBinding,
  } = req.body ?? {};

  if (client_id !== PAIRCT_CLIENT_ID) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'unknown client_id' });
  }
  if (typeof redirect_uri !== 'string' || !LOOPBACK_REDIRECT_URI_PATTERN.test(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri must be a loopback http://127.0.0.1:{port}/oidc/callback URL' });
  }
  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }
  // 타입까지 본다. 문자열이 아닌 값(JSON 숫자 등)이 들어오면 아래에서 문자열 메서드를
  // 부르다 터지고, express 기본 오류 처리가 500과 함께 **스택 트레이스(절대 경로 포함)**를
  // 응답에 실어 보낸다(2026-09-04 리뷰).
  if (typeof state !== 'string' || typeof nonce !== 'string' || !state || !nonce) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'state and nonce are required (strings)' });
  }
  if (typeof code_challenge !== 'string' || !code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'code_challenge (S256) is required (string)' });
  }
  if (!chain_id) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'chain_id is required' });
  }
  if (!requestBinding?.pk_i || !requestBinding?.signature) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'requestBinding.pk_i/signature are required' });
  }
  if (!zkpProof) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'zkpProof is required' });
  }

  // Structural check only — NOT a full Groth16 verify. pi_arid_i's first
  // public signal is uid, which the IdP doesn't know yet (login happens
  // later, at POST /authorize/login). Full verification happens there.
  try {
    assertDecimalSignals(zkpPublicSignals, 7, 'pi_i without uid');
  } catch (err) {
    return res.status(400).json({ error: 'invalid_request', error_description: err.message });
  }

  const bindingHash = keccak256(
    AbiCoder.defaultAbiCoder().encode(['string', 'string', 'string'], [state, nonce, code_challenge]),
  );
  let recovered;
  try {
    recovered = recoverAddress(bindingHash, requestBinding.signature);
  } catch (err) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'requestBinding.signature is malformed' });
  }
  if (recovered.toLowerCase() !== String(requestBinding.pk_i).toLowerCase()) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'requestBinding.signature does not match requestBinding.pk_i' });
  }

  const request_uri = `urn:pairct:par:${randomBytes(24).toString('hex')}`;
  pushedRequests.set(request_uri, {
    redirect_uri, state, nonce, code_challenge, code_challenge_method,
    zkpProof, zkpPublicSignals, chain_id, requestBinding,
    expiresAt: Date.now() + PAR_REQUEST_TTL_MS,
  });

  res.json({ request_uri, expires_in: PAR_REQUEST_TTL_MS / 1000 });
});

app.get('/authorize', (req, res) => {
  pruneExpired(pushedRequests);
  const { client_id, request_uri } = req.query;
  if (client_id !== PAIRCT_CLIENT_ID || !pushedRequests.has(request_uri)) {
    return res.status(400).send('Invalid or expired authorization request.');
  }
  res.sendFile(path.join(__dirname, 'idp', 'authorize.html'));
});

app.post('/authorize/login', async (req, res) => {
  pruneExpired(pushedRequests);
  const { request_uri, username, password } = req.body ?? {};
  const record = pushedRequests.get(request_uri);
  if (!record) {
    return res.status(400).json({ success: false, error: 'Invalid or expired authorization request' });
  }
  // 세션 바인딩은 **첫 로그인 성공에 고정**된다. 나중 로그인이 덮어쓸 수 있으면, 데모
  // 자격증명이 공개돼 있고 request_uri도 RP FE가 아는 값이라, 남이 같은 request_uri로
  // 로그인해 바인딩을 빼앗고 사용자의 동의를 영구히 403으로 만들 수 있다(반복 가능한 DoS).
  // 이미 다른 세션에 묶였으면 여기서 끊는다 — 비밀번호 확인보다도 앞이다.
  if (record.sessionId !== undefined && record.sessionId !== req.sessionID) {
    return res.status(409).json({
      success: false,
      error: 'this authorization request is already bound to another browser session',
    });
  }

  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
  // 계정 층 차단. 비밀번호 확인 직후, 증명 검증(비싼 snarkjs.groth16.verify) 전에 건다 —
  // 싼 검사가 먼저다. 두 로그인 경로(/authorize/login, verifyPiIAndIssueToken) 모두에서
  // 확인해야 한다 — pinAuidToAccount가 한쪽에만 있어 폐기가 우회됐던 전례가 있다.
  if (user.disabled) {
    return res.status(403).json({ success: false, error: 'Account is disabled' });
  }

  try {
    const verifySignals = [user.uid.toString(), ...record.zkpPublicSignals];
    assertDecimalSignals(verifySignals, 8, 'pi_i');

    // 비싼 groth16 검증 **앞에** 둔다(싼 검사가 먼저다).
    await assertMaxHeightWithinBound(verifySignals[3]);

    const isValid = await snarkjs.groth16.verify(vkeyAridI, verifySignals, record.zkpProof);
    if (!isValid) throw new Error('Identity Mismatch: This proof was not made for you!');

    const idpPubX = eddsa.F.toObject(idpEdDSAKeys.pub[0]).toString();
    const idpPubY = eddsa.F.toObject(idpEdDSAKeys.pub[1]).toString();
    if (String(verifySignals[6]) !== idpPubX || String(verifySignals[7]) !== idpPubY) {
      throw new Error('pi_i was proven against a different IdP key');
    }

    pinAuidToAccount(user, verifySignals[5]);

    // 이 인가 요청을 **로그인한 브라우저 세션**에 묶는다.
    //
    // request_uri는 비밀이 아니다: RP FE가 팝업을 그 URL로 보내야 하므로 지갑의
    // /loginStatus를 통해 RP에 전달된다. 그런데 IdP는 전역 와일드카드 cors()를 쓰므로,
    // 동의가 "request_uri를 안다"만으로 인가되면 RP 페이지가 사용자 대신 승인하거나
    // 거부할 수 있다 — 동의 단계가 통째로 우회된다(2026-09-04 리뷰).
    //
    // 세션에 묶으면 그 공격이 막힌다: 크로스 오리진 fetch는 credentials 없이는 idp_sid
    // 쿠키를 싣지 못하고, 와일드카드 CORS는 credentials를 허용하지 않는다.
    record.sessionId = req.sessionID;
    record.authenticatedUid = user.uid;
    record.arid_i = verifySignals[1];
    record.auid_i = verifySignals[2];
    record.max_height = verifySignals[3];
    record.token_nonce = verifySignals[4];
    record.auid = verifySignals[5];
  } catch (err) {
    return res.status(400).json({ success: false, error: err.message });
  }

  res.json({ success: true });
});

app.post('/authorize/consent', (req, res) => {
  pruneExpired(pushedRequests);
  const { request_uri, allowed } = req.body ?? {};
  const record = pushedRequests.get(request_uri);
  if (!record) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid or expired authorization request' });
  }
  if (!record.authenticatedUid) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Login has not completed for this request' });
  }
  // 로그인한 그 세션만 동의할 수 있다. request_uri는 RP FE도 아는 값이라(팝업을 그
  // URL로 보내야 한다) 지식만으로 인가하면 동의 단계가 우회된다 — /authorize/login의
  // record.sessionId 주석 참조.
  if (record.sessionId !== req.sessionID) {
    return res.status(403).json({
      error: 'access_denied',
      error_description:
        'consent must come from the browser session that logged in. Knowing the request_uri is not ' +
        'enough — the RP frontend also learns it.',
    });
  }

  pushedRequests.delete(request_uri); // single-use regardless of outcome

  if (!allowed) {
    return res.json({ redirectTo: `${record.redirect_uri}?error=access_denied&state=${encodeURIComponent(record.state)}` });
  }

  const code = randomBytes(24).toString('hex');
  authorizationCodes.set(code, {
    redirect_uri: record.redirect_uri,
    code_challenge: record.code_challenge,
    code_challenge_method: record.code_challenge_method,
    nonce: record.nonce,
    arid_i: record.arid_i,
    auid_i: record.auid_i,
    max_height: record.max_height,
    token_nonce: record.token_nonce,
    auid: record.auid,
    chain_id: record.chain_id,
    uid: record.authenticatedUid,
    expiresAt: Date.now() + AUTHORIZATION_CODE_TTL_MS,
  });

  res.json({ redirectTo: `${record.redirect_uri}?code=${code}&state=${encodeURIComponent(record.state)}` });
});

app.post('/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = req.body ?? {};

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  if (client_id !== PAIRCT_CLIENT_ID) {
    return res.status(400).json({ error: 'invalid_client' });
  }
  // 타입까지 본다 — 문자열이 아니면 아래 createHash().update()가 던지고, express 기본
  // 오류 처리가 500과 함께 스택 트레이스를 응답에 실어 보낸다(2026-09-04 리뷰).
  if (typeof code !== 'string' || typeof code_verifier !== 'string' || typeof redirect_uri !== 'string'
      || !code || !code_verifier || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'code, code_verifier, and redirect_uri are required (strings)' });
  }

  const record = authorizationCodes.get(code);
  if (!record || record.expiresAt <= Date.now()) {
    authorizationCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code is invalid, expired, or already used' });
  }
  if (record.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri does not match' });
  }

  const computedChallenge = createHash('sha256').update(code_verifier).digest('base64url');
  if (computedChallenge !== record.code_challenge) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier does not match code_challenge' });
  }

  // r_token(token_nonce) replay guard — same protection the old /consent_result
  // flow already has (verifyPiIAndIssueToken's usedNonces check), applied here
  // too so the new flow isn't weaker than the one it's meant to replace.
  if (usedNonces.has(String(record.token_nonce))) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'r_token has already been used to issue a statement' });
  }

  authorizationCodes.delete(code); // single-use: burn immediately after successful validation
  usedNonces.add(String(record.token_nonce));

  const exp = Math.floor(Date.now() / 1000) + 3600;
  const DOMAIN_PAIRCT_STATEMENT = valueToField('PAIRCT_STATEMENT');
  const msgFields = [
    DOMAIN_PAIRCT_STATEMENT,
    valueToField('custom-idp'),
    valueToField(PAIRCT_CLIENT_ID),
    valueToField(record.nonce),
    valueToField(record.arid_i),
    valueToField(record.auid_i),
    valueToField(record.token_nonce),
    valueToField(record.max_height),
    valueToField(record.chain_id),
  ];
  const msg = poseidon(msgFields);
  const sig = eddsa.signPoseidon(idpEdDSAKeys.prv, msg);

  // 온체인 tx 제출(wallet_agent.js의 /submitTransaction, pi_pk_i 회로)은 이미 배포된
  // PiPkIVerifier가 옛 6-field IDP_TOKEN 도메인 서명만 검증하도록 불변으로 고정돼
  // 있다. 회로/컨트랙트를 바꾸는 대신, 같은 값들로 그 옛 포맷 서명도 하나 더
  // 만들어서 새 statement와 함께 내려준다 — 둘은 서로 다른 도메인 분리자를 쓰는
  // 별개 서명이라 절대 섞어 쓸 수 없다.
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const idpTokenMsg = poseidon([
    DOMAIN_IDP_TOKEN,
    valueToField(record.arid_i),
    valueToField(record.auid_i),
    valueToField(record.token_nonce),
    valueToField(record.max_height),
    valueToField(record.chain_id),
  ]);
  const idpTokenSig = eddsa.signPoseidon(idpEdDSAKeys.prv, idpTokenMsg);

  // B2 authorized-opening trace logs — same bookkeeping the old
  // verifyPiIAndIssueToken does, so statements issued via this new flow stay
  // traceable through the existing /idp/lookup_uid_by_r_token and
  // /idp/lookup_uid_by_auid_i endpoints.
  // record는 authorizationCodes에서 꺼낸 이 handler 스코프의 값으로, max_height는
  // /authorize/login에서 pi_i의 4번째 public signal(verifySignals[3])로부터 채워졌다.
  // auidILog도 issuanceLog와 같은 { uid, maxHeight } 모양으로 저장한다 — 4-2번 축출이
  // 만료 기반이라 auidILog 쪽도 만료를 알아야 한다.
  issuanceLog.set(String(record.token_nonce), { uid: record.uid, maxHeight: record.max_height });
  auidILog.set(String(record.auid_i), { uid: record.uid, maxHeight: record.max_height });
  // 발급 기록은 /idp/revoke의 입구 검사가 조회하는 대상이라 반드시 살아남아야 한다.
  // 다만 로그인 자체를 막을 정도의 실패는 아니라고 판단해(가용성 우선), 저장이
  // 실패해도 statement는 정상 발급한다 — 대신 "이 세션은 재시작 후 폐기 불가"라는
  // 사실이 로그 한 줄로만 남지 않도록 응답에 persistenceWarning 필드를 구조적으로
  // 싣는다. 성공 시(대다수)에는 필드 자체를 넣지 않아 응답 모양이 그대로다.
  const persisted = saveIdPState();
  const persistenceWarning = persisted
    ? undefined
    : 'issuance record could not be persisted; this r_token cannot be revoked after an IdP restart until it is issued again';

  res.json({
    iss: 'custom-idp',
    aud: PAIRCT_CLIENT_ID,
    nonce: record.nonce,
    arid_i: record.arid_i,
    auid_i: record.auid_i,
    r_token: record.token_nonce,
    max_height: record.max_height,
    chain_id: record.chain_id,
    exp,
    ...(persistenceWarning ? { persistenceWarning } : {}),
    signature: {
      R8: [eddsa.F.toObject(sig.R8[0]).toString(), eddsa.F.toObject(sig.R8[1]).toString()],
      S: sig.S.toString(),
    },
    idpToken: {
      arid_i: record.arid_i,
      auid_i: record.auid_i,
      r_token: record.token_nonce,
      max_height: record.max_height,
      chain_id: record.chain_id,
      ...(persistenceWarning ? { persistenceWarning } : {}),
      signature: {
        R8: [eddsa.F.toObject(idpTokenSig.R8[0]).toString(), eddsa.F.toObject(idpTokenSig.R8[1]).toString()],
        S: idpTokenSig.S.toString(),
      },
    },
  });
});

// 1.5. Initial Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (user && user.password === password) {
    // Sign [domain, arid_i, auid_i, r_token, max_height, chain_id]
    const sig = psSign(["IDP_TOKEN", "init", "init", "0", "0", "0"]);
    res.json({
      success: true,
      authToken: {
        uid: user.uid,
        sub: user.sub,
        signature: sig,
        issuer: 'custom-idp'
      }
    });
  } else {
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
});

// 2. Popup Login Page
app.get('/login_popup', (req, res) => {
  const start = cursor();
  console.log(`[CustomIdP][Step 9] Login popup requested. ${ms(start)}`);
  res.sendFile(path.join(__dirname, 'idp', 'login_popup.html'));
});

// 3. ZKP + Credentials SSO Endpoint
app.post('/sso_with_credentials', async (req, res) => {
  const start = cursor();
  const { username, password, zkpProof, zkpPublicSignals, business, walletSubmission, pi_i } = req.body;

  console.log(`--- [CustomIdP][Step 9] SSO Attempt: ${username} (Mode 2 pi_i) ---`);
  console.log(`[CustomIdP][Step 9] Published endpoint hit: POST /sso_with_credentials ${ms(start)}`);
  console.log('[CustomIdP][Step 9] Wallet submission fields:', {
    auid_i: summarizeValue(walletSubmission?.auid_i ?? business?.auid_i),
    arid_i: summarizeValue(walletSubmission?.arid_i ?? business?.arid_i),
    r_token: summarizeValue(walletSubmission?.r_token ?? business?.r_token ?? business?.tokenNonce),
    pi_i: summarizeValue(walletSubmission?.pi_i ?? pi_i ?? zkpProof),
    r_i: summarizeValue(walletSubmission?.r_i ?? business?.r_i),
    r_i_check: Boolean(walletSubmission?.r_i ?? business?.r_i)
  });

  const user = users[username];
  if (!user || user.password !== password) {
    console.error(`❌ [CustomIdP][Step 9] Login Failed: Invalid credentials for ${username} ${ms(start)}`);
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  // 비밀번호 인증을 통과한 이 시도(username + 그때 제출된 proof/business)를 세션에
  // 고정해둔다. /consent_result는 이후 요청 본문을 신뢰하지 않고 이 값만 사용한다 —
  // 그래야 /sso_with_credentials를 건너뛰고 /consent_result만 직접 호출하거나, 여기서
  // 검증된 것과 다른 proof/business로 바꿔치기하는 걸 막을 수 있다.
  req.session.pendingPairCT = {
    username,
    zkpProof,
    zkpPublicSignals,
    business,
    createdAt: Date.now(),
  };

  console.log(`[CustomIdP][Step 9] Login verified for ${username}. Waiting for consent before pi_i verification. ${ms(start)}`);
  res.json({ success: true, pendingConsent: true });
});

async function verifyPiIAndIssueToken({ username, zkpProof, zkpPublicSignals, business, start = cursor() }) {
  const user = users[username];
  if (!user) throw new Error('Unknown user for consent verification');
  // 계정 층 차단. 비밀번호는 이미 /sso_with_credentials가 확인했으므로(그 결과가
  // req.session.pendingPairCT로 넘어와 이 함수가 호출됨), 여기서는 증명 검증(비싼
  // snarkjs.groth16.verify, 아래 try 블록) 전에 두는 것으로 "싼 검사 먼저" 순서를
  // 지킨다. /authorize/login과 마찬가지로 두 로그인 경로 모두에서 확인해야 한다.
  if (user.disabled) throw new Error('Account is disabled');

  try {
    if (!zkpProof || !zkpPublicSignals) throw new Error('ZKP data missing');
    assertDecimalSignals(zkpPublicSignals, 7, 'pi_i without uid');

    // The wallet/RP popup payload omits pi_i's public UID signal. The IdP
    // reconstructs it from the authenticated popup account before verification.
    const verifySignals = [user.uid.toString(), ...zkpPublicSignals];
    assertDecimalSignals(verifySignals, 8, 'pi_i');
    console.log(`[CustomIdP][Step 10] BINDING: using Session UID(${summarizeValue(user.uid)}) as pi_i UID input ${ms(start)}`);

    const isValid = await snarkjs.groth16.verify(vkeyAridI, verifySignals, zkpProof);

    if (!isValid) {
      throw new Error('Identity Mismatch: This proof was not made for you!');
    }

    // pk_IdP_x/y (7th, 8th public signals) prove the circuit's internal
    // RP-registration-credential signature check ran against a real key — but
    // the circuit itself doesn't know which key is "the real IdP's," so it
    // only constrains internal consistency (signature verifies under
    // *whatever* pk_IdP_x/y was supplied). The IdP must additionally check
    // here that the supplied key is actually its own, otherwise a prover could
    // pass a self-chosen key + self-forged signature and this whole check
    // would be a no-op.
    const idpPubX = eddsa.F.toObject(idpEdDSAKeys.pub[0]).toString();
    const idpPubY = eddsa.F.toObject(idpEdDSAKeys.pub[1]).toString();
    if (String(verifySignals[6]) !== idpPubX || String(verifySignals[7]) !== idpPubY) {
      throw new Error('pi_i was proven against a different IdP key (RP registration credential check bypassed)');
    }

    pinAuidToAccount(user, verifySignals[5]);

    const maxHeight = business?.maxHeight ?? business?.max_height;
    const rToken = business?.r_token ?? business?.tokenNonce;
    if (String(verifySignals[1]) !== String(business?.arid_i)) throw new Error('arid_i does not match pi_i public signal');
    if (String(verifySignals[2]) !== String(business?.auid_i)) throw new Error('auid_i does not match pi_i public signal');
    if (String(verifySignals[3]) !== String(maxHeight)) throw new Error('max_height does not match pi_i public signal');
    // 두 로그인 경로 모두에서 상한을 걸어야 한다 — pinAuidToAccount가 한쪽에만 있어
    // 폐기가 우회됐던 전례가 있다(2026-08-26).
    await assertMaxHeightWithinBound(verifySignals[3]);
    if (String(verifySignals[4]) !== String(rToken)) throw new Error('r_token does not match pi_i public signal');
    console.log(`✅ [CustomIdP][Step 10] pi_i Verified for user: ${username} ${ms(start)}`);
  } catch (err) {
    console.error(`❌ [CustomIdP][Step 10] pi_i Error: ${err.message} ${ms(start)}`);
    throw err;
  }

  // rp_nonce is never sent to the IdP (it would let the IdP recover rid via
  // arid_i / rp_nonce). r_i (mode2SessionNonce) is NOT usable for replay
  // protection here: it is never checked against the pi_i proof's public
  // signals above, so resubmitting an already-used proof with only r_i
  // changed would sail through undetected. r_i keeps its existing role as
  // the RP FE's own transient flow-correlation nonce (client.js matches it
  // against mode2SessionNonce when IDP_SSO_SUCCESS arrives); nothing about
  // that role changes here. Replay protection is instead keyed off
  // r_token, which is checked against verifySignals[4] above and so
  // cannot be forged or reused for a different proof.
  const maxHeight = business?.maxHeight ?? business?.max_height;
  const chainId = business?.chain_id ?? business?.chainId;
  const rToken = business?.r_token ?? business?.tokenNonce;
  if (!rToken) throw new Error('r_token missing from Wallet submission');
  if (!maxHeight) throw new Error('max_height missing from Wallet submission');
  if (!chainId) throw new Error('chain_id missing from Wallet submission');

  if (usedNonces.has(String(rToken))) {
    throw new Error('Replay detected: r_token was already used');
  }
  usedNonces.add(String(rToken));

  const exp = Math.floor(Date.now() / 1000) + 3600;

  // PS('IDP_TOKEN', ...) 대신 EdDSA-Poseidon: 6개 필드를 Poseidon으로 하나의 값으로 묶은
  // 뒤 그 값을 서명한다. domain 문자열도 다른 필드처럼 valueToField()로 필드 원소화한다
  // (Poseidon은 문자열을 직접 못 받음 — hashToFr()는 mcl 전용이라 여기 못 씀).
  const DOMAIN_IDP_TOKEN = valueToField('IDP_TOKEN');
  const msgFields = [
    DOMAIN_IDP_TOKEN,
    valueToField(business.arid_i),
    valueToField(business.auid_i),
    valueToField(rToken.toString()),
    valueToField(maxHeight.toString()),
    valueToField(chainId.toString()),
  ];
  // poseidon(...)의 원본 반환값을 그대로 signPoseidon에 넘긴다 — .toObject()로 변환한
  // BigInt를 넘기면 안 된다 (F-internal 표현이 필요함, tests/test_eddsa.js 참고).
  const msg = poseidon(msgFields);
  const sig = eddsa.signPoseidon(idpEdDSAKeys.prv, msg);
  const sigJson = {
    R8: [
      eddsa.F.toObject(sig.R8[0]).toString(),
      eddsa.F.toObject(sig.R8[1]).toString(),
    ],
    S: sig.S.toString(),
  };
  console.log(`[CustomIdP][Step 10] Issuing IdP auth token after consent and pi_i verification. ${ms(start)}`);

  // maxHeight는 이 함수 위쪽에서 business.maxHeight ?? business.max_height로 이미
  // 채워진 지역 변수다(줄 658 부근). auidILog도 issuanceLog와 같은 { uid, maxHeight }
  // 모양으로 저장한다 — 4-2번 축출이 만료 기반이라 auidILog 쪽도 만료를 알아야 한다.
  issuanceLog.set(rToken.toString(), { uid: user.uid, maxHeight: maxHeight.toString() });
  auidILog.set(String(business.auid_i), { uid: user.uid, maxHeight: maxHeight.toString() });
  // 발급 기록은 /idp/revoke의 입구 검사가 조회하는 대상이라 반드시 살아남아야 한다.
  // /token 핸들러와 동일한 정책: 저장 실패가 로그인 자체를 막지는 않되(가용성 우선),
  // "재시작 후 폐기 불가"라는 사실을 로그 한 줄이 아니라 응답 구조로 드러낸다.
  const persisted = saveIdPState();
  const idpToken = {
    arid_i: business.arid_i,
    auid_i: business.auid_i,
    r_token: rToken.toString(),
    max_height: maxHeight.toString(),
    chain_id: chainId.toString(),
    exp: exp,
    ...(persisted ? {} : {
      persistenceWarning: 'issuance record could not be persisted; this r_token cannot be revoked after an IdP restart until it is issued again',
    }),
    signature: sigJson
  };
  console.log(`[CustomIdP][Step 11] IdP auth token issued and returned for Wallet delivery. ${ms(start)}`);

  return idpToken;
}

app.post('/consent_result', async (req, res) => {
  const start = cursor();
  const { allowed } = req.body || {};

  // username/zkpProof/zkpPublicSignals/business는 요청 본문을 신뢰하지 않는다 — 반드시
  // /sso_with_credentials에서 비밀번호 인증과 함께 이 세션에 저장해둔 값만 쓴다. 성공/실패/
  // 거부 어느 경우든 한 번 쓰면 즉시 지워서 같은 pending 로그인을 재사용하지 못하게 막는다.
  const pending = req.session.pendingPairCT;
  delete req.session.pendingPairCT;

  if (!pending) {
    return res.status(400).json({ success: false, error: 'No pending login for this session' });
  }
  if (Date.now() - pending.createdAt > PENDING_CONSENT_TTL_MS) {
    return res.status(400).json({ success: false, error: 'Pending login expired, please sign in again' });
  }

  const { username, zkpProof, zkpPublicSignals, business } = pending;

  console.log('[CustomIdP][Step 10] Consent result received:', {
    username: summarizeValue(username),
    allowed: Boolean(allowed),
    auid_i: summarizeValue(business?.auid_i),
    arid_i: summarizeValue(business?.arid_i),
    r_token: summarizeValue(business?.r_token ?? business?.tokenNonce)
  });

  if (!allowed) {
    return res.json({ success: false, error: 'Consent denied' });
  }

  try {
    console.log(`[CustomIdP][Step 10] Consent approved. Verifying pi_i now. ${ms(start)}`);
    const idpToken = await verifyPiIAndIssueToken({ username, zkpProof, zkpPublicSignals, business, start });
    console.log(`[CustomIdP][Step 11] Consent flow complete, responding to RP FE. ${ms(start)}`);
    res.json({ success: true, idpToken });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message || 'pi_i verification failed' });
  }
});

// 3.5. B2 Trace Endpoint: Lookup UID by r_token
// requireIdPAuditor를 건다 — 이전에는 인증이 전혀 없어서 r_token 하나를 아는
// 아무나 uid/username을 얻을 수 있었다. 상태 영속화 전에는 "마지막 재시작 이후"로
// 노출 창이 자연히 닫혔지만, 이제 issuanceLog가 영구히 쌓이므로 그 창이 무기한
// 열려 있었다. requireIdPAdmin이 아니라 별도의 requireIdPAuditor를 쓰는 이유는
// 아래 requireIdPAuditor 정의부 주석 참고(추적 권한과 폐기 권한 분리). 이
// 엔드포인트를 실제로 호출하는 코드는(grep으로 확인) 이 저장소 안에 없다 — 도입
// 계획 문서(docs/superpowers/plans/2026-07-16-b2-transaction-tracing-plan.md)에만
// 언급되고 실제 소비자는 구현되지 않았다.
// 감사자 자격만 판정하고 아무것도 돌려주지 않는다(부수효과 없음).
//
// 왜 필요한가. RP 백엔드(server.js)는 B2 추적 요청을 IdP로 넘기는 통로인데, 감사자
// 시크릿을 보유하지 않으므로 **자격의 유효성을 스스로 판단할 수 없다.** 그래서 헤더
// 존재만 보고 넘어가면, 잘못된 자격을 든 호출자도 RP의 로컬 조회까지 도달해
// 404(모르는 지갑)와 그 외의 차이로 "이 지갑이 이 RP에 로그인한 적 있는지"를 알아낼 수
// 있다(2026-09-04 리뷰). RP가 조회 전에 이 엔드포인트로 자격을 먼저 확인하게 한다.
app.post('/idp/auditor/check', requireIdPAuditor, (req, res) => {
  res.json({ ok: true });
});

app.post('/idp/lookup_uid_by_r_token', requireIdPAuditor, (req, res) => {
  const { r_token } = req.body ?? {};
  if (!r_token) {
    return res.status(400).json({ error: 'r_token is required' });
  }
  // issuanceLog는 이제 { uid, maxHeight }를 저장한다(만료 판정을 위해 /idp/revoke가
  // maxHeight도 조회해야 하므로). 이 엔드포인트의 응답 형태({ uid, username })는
  // 외부 계약이라 바뀌지 않는다 — 내부에서 uid만 꺼내 쓴다.
  const entry = issuanceLog.get(String(r_token));
  if (entry === undefined) {
    return res.status(404).json({ error: 'No issuance record found for this r_token' });
  }
  const uid = entry.uid;
  // uid는 users의 값일 뿐 키가 아니라서, 사람이 읽을 수 있는 username을 보여주려면
  // 역방향으로 찾아야 한다.
  const usernameEntry = Object.entries(users).find(([, user]) => String(user.uid) === String(uid));
  res.json({ uid, username: usernameEntry ? usernameEntry[0] : null });
});

// 3.6. B2 Trace Endpoint: Lookup UID by auid_i
// requireIdPAuditor를 건다(위 requireIdPAuditor 정의부 주석과 동일한 이유 —
// 추적 권한과 폐기 권한 분리). server.js의 POST /api/mode2/trace_transaction이
// 이 엔드포인트를 호출하며(server.js:986 부근), X-IdP-Auditor-Secret 헤더를
// 붙여 보낸다(server.js의 IDP_AUDITOR_SECRET 환경변수에서 읽음).
app.post('/idp/lookup_uid_by_auid_i', requireIdPAuditor, (req, res) => {
  const { auid_i } = req.body ?? {};
  if (!auid_i) {
    return res.status(400).json({ error: 'auid_i is required' });
  }
  // v2부터 auidILog도 issuanceLog와 같은 { uid, maxHeight } 모양이다(4-2번 만료 기반
  // 축출을 적용하려면 만료 정보가 필요해서). 응답 형태({ uid, username })는 외부
  // 계약이라 바뀌지 않는다.
  const entry = auidILog.get(String(auid_i));
  if (entry === undefined) {
    return res.status(404).json({ error: 'No issuance record found for this auid_i' });
  }
  const uid = entry.uid;
  const usernameEntry = Object.entries(users).find(([, user]) => String(user.uid) === String(uid));
  res.json({ uid, username: usernameEntry ? usernameEntry[0] : null });
});

// /idp/revoke는 운영자 전용 엔드포인트다. 인증 없이 열어두면 임의의 웹페이지가
// 전역 app.use(cors())를 타고 폐기를 유발해 root를 흔들 수 있고, 게시된 root와
// IdP root가 어긋나 모든 사용자의 execute()가 revert하는 무인증 DoS가 된다.
//
// 시크릿은 환경변수 IDP_ADMIN_SECRET에서만 읽는다(하드코딩 금지). 미설정이면
// 조용히 인증을 건너뛰지 않고 503으로 명확히 거부한다.
const IDP_ADMIN_SECRET = process.env.IDP_ADMIN_SECRET;

function secretMatches(provided, expected) {
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  // timingSafeEqual은 길이가 다르면 throw하므로 길이를 먼저 비교한다.
  // 길이 노출은 감수한다(내용 비교만 상수 시간으로 유지).
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function requireIdPAdmin(req, res, next) {
  if (!IDP_ADMIN_SECRET) {
    return res.status(503).json({ error: 'revocation endpoint is disabled: IDP_ADMIN_SECRET is not configured' });
  }
  // 전역 cors()는 다른 엔드포인트가 의존하므로 건드리지 않고, 이 엔드포인트에만
  // 오리진 제한을 건다. 브라우저는 cross-origin 요청에 항상 Origin 헤더를 붙이므로,
  // Origin이 있다는 것은 곧 브라우저에서 온 요청이라는 뜻이다. 운영자 도구(curl,
  // node 스크립트)는 Origin을 붙이지 않는다.
  const origin = req.get('Origin');
  if (origin !== undefined) {
    return res.status(403).json({ error: 'browser-originated requests are not allowed on this endpoint' });
  }
  const provided = req.get('X-IdP-Admin-Secret');
  if (typeof provided !== 'string' || !secretMatches(provided, IDP_ADMIN_SECRET)) {
    // 시크릿 값 자체는 로그에도 응답에도 남기지 않는다.
    console.warn('[IdP] rejected unauthenticated /idp/revoke attempt');
    return res.status(401).json({ error: 'invalid or missing admin secret' });
  }
  return next();
}

// B2 추적 엔드포인트(/idp/lookup_uid_by_r_token, /idp/lookup_uid_by_auid_i) 전용
// 인증. 추적(신원 역추적, conditional privacy의 감사 기능)과 폐기(/idp/revoke,
// /idp/publish/*)는 서로 다른 권한이어야 한다 — 폐기 권한을 가진 관리자가 자동으로
// 추적 권한도 갖는다면(또는 그 반대라면) 권한 분리가 이름뿐인 것이 된다. 그래서
// IDP_ADMIN_SECRET과 값을 공유하지 않는 별도의 IDP_AUDITOR_SECRET을 쓴다.
// requireIdPAdmin과 구조는 동일하게 맞춘다(timingSafeEqual 비교, 미설정 시 503,
// Origin 헤더가 있으면 403). 관리자 시크릿을 여기 헤더에 넣어도 값이 다르므로
// secretMatches가 실패해 401이 된다 — 이 실패가 바로 의도된 권한 분리다.
const IDP_AUDITOR_SECRET = process.env.IDP_AUDITOR_SECRET;

function requireIdPAuditor(req, res, next) {
  if (!IDP_AUDITOR_SECRET) {
    return res.status(503).json({ error: 'trace endpoint is disabled: IDP_AUDITOR_SECRET is not configured' });
  }
  const origin = req.get('Origin');
  if (origin !== undefined) {
    return res.status(403).json({ error: 'browser-originated requests are not allowed on this endpoint' });
  }
  const provided = req.get('X-IdP-Auditor-Secret');
  if (typeof provided !== 'string' || !secretMatches(provided, IDP_AUDITOR_SECRET)) {
    // 시크릿 값 자체는 로그에도 응답에도 남기지 않는다.
    console.warn('[IdP] rejected unauthenticated B2 trace attempt');
    return res.status(401).json({ error: 'invalid or missing auditor secret' });
  }
  return next();
}

// 폐기 대상 등록. type='session'이면 r_token, 'account'면 auid를 값으로 받는다.
// 어느 쪽이든 IdP가 이미 알고 있는 값이다(issuanceLog / user.lastAuid).
// 폐기 상태를 바꾸는 관리자 경로(/idp/revoke, publish/prepare, publish/commit)를
// 한 줄로 세운다.
//
// 왜 필요한가. commit 핸들러는 "prepare와 commit 사이에 폐기 상태를 바꾸는 경로는
// 없다(admin 직렬)"를 전제로 적혀 있지만, express는 요청을 동시에 처리하고 이 경로들은
// 전부 RPC·Poseidon await를 품고 있어 실제로는 인터리브된다. 겹친 commit 두 건이 같은
// 서브트리를 동시에 전진시키면 회차가 뒤섞이고, 운영자가 push하는 root가 어느 회차의
// 것인지 알 수 없게 된다.
let adminMutationChain = Promise.resolve();
function serializeAdminMutation(handler) {
  return (req, res, next) => {
    const run = adminMutationChain.then(() => handler(req, res, next));
    adminMutationChain = run.then(
      () => {},
      () => {},
    );
    // 핸들러가 던지면 express의 기본 오류 처리로 넘긴다(응답이 없는 채 매달리지 않게).
    run.catch(next);
  };
}

app.post('/idp/revoke', requireIdPAdmin, serializeAdminMutation(async (req, res) => {
  const { type, value } = req.body ?? {};
  if (value === undefined || value === null) {
    return res.status(400).json({ error: 'value is required' });
  }

  // Reject non-numeric values: only decimal digits (after trimming) are allowed.
  const valueStr = String(value).trim();
  if (!/^[0-9]+$/.test(valueStr)) {
    return res.status(400).json({ error: 'value must be a non-empty decimal number' });
  }

  // 상한은 BN254 필드 크기 p다. 여기서 걸러야 하는 것은 "필드 원소가 아닌 입력"뿐이다.
  // 폐기 대상(r_token = Poseidon(...), auid = Poseidon(uid, salt))은 둘 다 Poseidon
  // 출력이라 [0, p)에 균등 분포한다. 예전에는 상한이 2^252였는데, 그러면 정상 대상의
  // 약 67%(1 - 2^252/p)가 400으로 거부되면서 폐기가 조용히 실패했다.
  // lib/imt.js의 leafValue()가 Poseidon '출력'을 & MASK_252로 정규화하므로
  // 252비트 제약은 리프 값에만 적용되며 입력에 적용해서는 안 된다.
  try {
    const valueBigInt = BigInt(valueStr);
    if (valueBigInt >= FIELD_PRIME) {
      return res.status(400).json({ error: 'value must be less than the BN254 field prime' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'value must be a valid number' });
  }

  let tag;
  if (type === 'session') tag = TAG_SESSION;
  else if (type === 'account') tag = TAG_ACCOUNT;
  else return res.status(400).json({ error: "type must be 'session' or 'account'" });

  let currentBlock;
  try {
    currentBlock = await getCurrentBlockHeight();
  } catch (err) {
    return res.status(502).json({ error: `failed to read current block height: ${err.message}` });
  }

  // 입구 검사: 리프마다 만료 블록을 부여한다(트리 수명 관리, docs/REVOCATION_FOLLOWUPS.md).
  // 부수 효과로, 세션 폐기는 "내가 발급한 적 있는 r_token인가"를 issuanceLog에서
  // 먼저 확인하게 되어 임의의 숫자로 트리를 부풀리는 오염이 원천 차단된다.
  let expiryBlock;
  if (type === 'session') {
    const issued = issuanceLog.get(valueStr);
    if (issued === undefined) {
      // 발급한 적 없는 값: "잘못된 값"과 구분해 운영자가 원인을 알 수 있게 404로 응답한다.
      return res.status(404).json({ error: 'no issuance record found for this r_token; only IdP-issued sessions can be revoked' });
    }
    const maxHeight = BigInt(issued.maxHeight);
    if (maxHeight <= currentBlock) {
      // 이미 만료된 크레덴셜: 넣어봐야 지갑이 비멤버십 증명을 못 만드는 것도 아니고
      // (회로가 max_height 자체로 거부) 트리만 불필요하게 커지므로, "잘못된 값"(404)과는
      // 다른 상태 코드(410 Gone)로 구분한다.
      return res.status(410).json({ error: 'credential already expired; revocation would be a no-op' });
    }
    expiryBlock = maxHeight;
  } else {
    // 계정 폐기는 항상 통과한다. 폐기 직전에 발급된 크레덴셜까지 덮어야 하므로 만료
    // 블록은 "현재 블록 + 크레덴셜 수명"이다.
    //
    // 여기에 MAX_HEIGHT_SLACK_BLOCKS를 더해야 한다. 발급 상한이
    // currentBlock + CREDENTIAL_LIFETIME_BLOCKS + MAX_HEIGHT_SLACK_BLOCKS까지 허용하므로,
    // 여유 없이 잡으면 그 폭만큼 구간이 열린다: 폐기 리프는 만료로 회수되는데 크레덴셜은
    // 아직 살아 있어 계정 비멤버십을 다시 통과한다. 상한을 넓힌 만큼 폐기 창도 넓힌다.
    // (2026-09-04 리뷰. tests/test_idp_publish_behavior.mjs 케이스 3-e가 고정한다.)
    expiryBlock = currentBlock + CREDENTIAL_LIFETIME_BLOCKS + MAX_HEIGHT_SLACK_BLOCKS;
  }

  try {
    const leaf = await leafValue(tag, valueStr);
    const leafKey = leaf.toString();

    // 게시 트리는 여기서 건드리지 않는다. 대기열에만 넣고, 실제 반영은
    // /idp/publish/prepare + /idp/publish/commit이 한다.
    const alreadyPublished = await revocationV3.hasLeaf(leafKey);
    const alreadyPending = pendingAdds.has(leafKey);
    // 게시돼 있어도 **이미 만료된** 리프면 대기열에 넣는다. 만료 회수는 만료된 리프를
    // 트리에서 빼는데, prepare가 회차를 동결한 뒤 이 재폐기가 들어오면 그 회차의 commit이
    // 리프를 회수해 버려 방금 접수한 폐기가 흔적 없이 사라질 수 있다(만료 메타데이터 고아
    // 정리까지 함께 지운다). 대기열에 있으면 그 회차에서 빠지더라도 다음 회차에 다시
    // 들어간다. 트리에 그대로 남는 평범한 경우에는 prepare의 hasLeaf 필터가 걸러 무해하고,
    // commit의 대기열 정리가 '게시됨'으로 보고 지운다.
    //
    // 아래에서 leafExpiry와 v3의 accountExpiry를 **더 늦은 만료로 갱신**하므로, 실제로는
    // 그 회차의 회수가 이 리프를 건드리지 않고 지나간다 — 리프가 트리에 그대로 남은 채
    // 만료만 연장되는 것이 재폐기의 올바른 최종 상태다.
    const publishedButExpired = alreadyPublished && (() => {
      const e = leafExpiry.get(leafKey);
      return e !== undefined && e <= currentBlock;
    })();
    const addedToPending = (!alreadyPublished || publishedButExpired) && !alreadyPending;
    if (addedToPending) pendingAdds.add(leafKey);

    // 재폐기는 에러가 아니라 no-op이다. 다만 계정 재폐기는 폐기 창을 연장해야
    // 하므로(새로 발급된 크레덴셜까지 덮어야 한다) 만료 블록은 더 늦은 쪽으로
    // 갱신한다. 짧은 쪽으로 덮어쓰면 창이 줄어 폐기가 조기에 풀린다.
    const previousExpiry = leafExpiry.get(leafKey);
    const hadPreviousExpiry = previousExpiry !== undefined;
    const effectiveExpiry =
      hadPreviousExpiry && previousExpiry > expiryBlock ? previousExpiry : expiryBlock;
    leafExpiry.set(leafKey, effectiveExpiry);

    // v3: 리프가 어느 층인지 여기서만 알 수 있다(리프는 Poseidon 해시라 나중에 되돌릴
    // 수 없다). 게시 시점에 알맞은 포레스트로 라우팅하려면 지금 기억해 둬야 한다.
    // 세션 샤드는 **그 크레덴셜의 max_height**로 정해진다. effectiveExpiry(= 여러 번
    // 접수됐을 때의 더 늦은 만료)를 넘기면 리프가 틀린 샤드로 조용히 들어간다.
    // 지금은 둘이 같지만 그건 불변식이 아니라 우연이므로 의존하지 않는다.
    const v3Undo = revocationV3.record(
      leafKey,
      type === 'session' ? LAYER_SESSION : LAYER_ACCOUNT,
      type === 'session'
        ? { expiry: effectiveExpiry, maxHeight: expiryBlock }
        : { expiry: effectiveExpiry },
    );

    // 대기열과 만료 메타데이터가 재시작을 넘어 살아남아야 접수된 폐기가 사라지지 않는다.
    // 폐기는 보안 조작이라 저장 실패를 200으로 감추면 안 된다 — 저장이 실패하면 이
    // 요청이 만든 인메모리 변경을 롤백하고(이번 요청이 건드리지 않은 기존 항목은
    // 그대로 둔다) 5xx로 응답해 운영자가 재시도하게 한다. 롤백하지 않고 인메모리
    // 상태만 전진시키면, 응답은 실패라고 말하는데 다음 /idp/publish/prepare가 이
    // 폐기를 그대로 집어 게시해버리는 모순이 생긴다 — 응답과 실제 상태가 어긋나는
    // 쪽보다는, 재시도하면 항상 같은 결과가 나오는 쪽(진짜 아무 일도 안 일어남)이 낫다.
    const saved = saveIdPState();
    if (!saved) {
      if (addedToPending) pendingAdds.delete(leafKey);
      if (hadPreviousExpiry) leafExpiry.set(leafKey, previousExpiry);
      else leafExpiry.delete(leafKey);
      revocationV3.unrecord(leafKey, v3Undo);
      return res.status(500).json({
        error: 'failed to persist revocation state; the revocation was not recorded, please retry',
      });
    }

    // 응답에 root를 담지 않는다 — 아직 게시되지 않았으므로 '새 root'라는 것이
    // 존재하지 않고, 담으면 호출자가 그 값을 게시된 것으로 오해한다.
    console.log(
      `[IdP] queued revocation of ${type} -> leaf ${leafKey}, expires at block ${effectiveExpiry}` +
        ` (published=${alreadyPublished}, alreadyPending=${alreadyPending}, pending=${pendingAdds.size})`,
    );
    // expiryBlock은 BigInt라 JSON.stringify가 던진다. 문자열로 내보낸다.
    res.json({
      pending: true,
      leaf: leafKey,
      expiryBlock: effectiveExpiry.toString(),
      alreadyPublished,
      alreadyPending,
      pendingCount: pendingAdds.size,
    });
  } catch (err) {
    return res.status(400).json({ error: err.message || 'Failed to revoke value' });
  }
}));

// 관리자 전용 게시 엔드포인트 (prepare/commit 2단계).
//
// 왜 한 번에 하지 않는가: "IdP는 전진했는데 온체인 push는 실패" 상태가 생기면 지금
// 고치려는 문제(게시되지 않은 root로 witness를 만들어 전원이 막힘)가 그대로 재발한다.
// push가 확정된 뒤에만 IdP가 전진하도록 순서를 강제한다.
//   prepare 후 push 실패 -> 아무것도 안 바뀜(안전)
//   push 후 commit 실패  -> 체인의 latestRoot는 이미 새 root로 전진했는데 IdP는 옛
//                           리프 집합을 계속 서빙한다. grace window가 없으므로 지갑이
//                           그 옛 리프 집합으로 만드는 root는 latestRoot와 다르고,
//                           StaleRevocationRoot로 전원(폐기와 무관한 사용자 포함)이
//                           막힌다 — 더 이상 "안전한 방향"이 아니라 전면 장애다.
//                           이 창을 좁히는 수단은 push 성공 뒤 commit 실패 시 즉시
//                           재시도하는 것뿐이다(scripts/revocation_sweep.cjs의 커밋
//                           즉시 재시도 로직 참고). 그래도 재시도가 모두 실패하면
//                           운영자가 수동으로 /idp/publish/commit을 다시 호출해야 한다.
//
// 만료 리프 제거(sweep)도 이 경로에 흡수됐다. 만료된 리프를 빼야 지갑의 매 트랜잭션
// 재구성 비용이 무한정 늘지 않는다(docs/REVOCATION_FOLLOWUPS.md 0절).
// 인증은 /idp/revoke와 동일한 requireIdPAdmin을 재사용한다.
app.post('/idp/publish/prepare', requireIdPAdmin, serializeAdminMutation(async (req, res) => {
  let currentBlock;
  try {
    currentBlock = await getCurrentBlockHeight();
  } catch (err) {
    return res.status(502).json({ error: `failed to read current block height: ${err.message}` });
  }

  const isExpired = (leafKey) => {
    const e = leafExpiry.get(leafKey);
    return e !== undefined && e <= currentBlock;
  };

  // 새로 게시될 리프 = 대기 중이고 아직 v3에 없는 것.
  //
  // **여기서 만료된 대기 리프를 거르지 않는다.** "이미 만료됐으니 슬롯만 먹는다"는
  // 최적화는 계정 폐기에서 건전하지 않다: 계정 폐기의 만료는 접수 시점 +
  // CREDENTIAL_LIFETIME_BLOCKS로 고정되고(세션과 달리 실제 크레덴셜의 max_height가 아니다),
  // 계정 폐기는 disabled를 세우지 않으므로 그 계정은 재로그인해 더 늦은 max_height를 가진
  // 크레덴셜을 받을 수 있다. 게시가 지연돼 접수 리프를 "만료"로 버리면 그 크레덴셜을 막을
  // 것이 사라진다 — 폐기가 조용히 무효가 되는 방향의 실패다.
  // (tests/test_idp_publish_behavior.mjs가 이 불변식을 고정한다.)
  const addedValues = [];
  for (const leafKey of pendingAdds) {
    if (!(await revocationV3.hasLeaf(leafKey))) addedValues.push(leafKey);
  }

  const publishedNow = publishedLeaves();
  const expiredCount = publishedNow.filter(isExpired).length;

  // === 회차 토큰 ===
  //
  // v2 시절 이 자리에는 "다음 게시 root 예측"이 있었고 commit이 그 root 일치로 회차를
  // 확정했다. v3에서는 그럴 수 없고 그럴 필요도 없다: 게시 순서가 prepare -> commit ->
  // push라 게시할 root는 commit이 포레스트를 전진시킨 **뒤에야** 정해진다(설계 문서
  // 13.1절). 회차 합의에 필요한 것은 "이 commit이 그 prepare의 것인가"뿐이므로 불투명한
  // 토큰이면 충분하다 — 그리고 root를 미리 계산하지 않으므로 트리 전체를 시뮬레이션하던
  // 비용도 사라진다.
  const roundToken = randomBytes(16).toString('hex');

  // 여러 번 호출하면 마지막 것이 유효하다. prepare와 commit 사이에 들어온 폐기는
  // 이번 회차에 포함되지 않고 다음 회차로 넘어간다 — 의도된 동작이다.
  preparedPublish = {
    roundToken,
    addedValues,
    blockHeight: currentBlock,
  };

  const shardStats = revocationV3.usage();
  console.log(
    `[IdP] publish/prepare at block ${currentBlock}: +${addedValues.length} ` +
      `(expired published ${expiredCount}), published ${publishedNow.length}, round ${roundToken}`,
  );
  // 추가가 0건이어도 200이다 — 그 경우가 heartbeat다(같은 root를 다시 게시하는 no-op).
  res.json({
    roundToken,
    // 지금 게시돼 있는 root. 새 root는 commit이 돌려준다.
    currentRoot: revocationV3.combinedRoot(),
    added: addedValues.length,
    // 게시된 리프 중 이미 만료된 개수 = 이번 commit이 회수할 수 있는 상한.
    // 세션 층은 샤드 리셋으로, 계정 층은 샤드 재기준화로 회수한다(설계 문서 3.2절).
    expiredPublished: expiredCount,
    leafCount: publishedNow.length,
    pendingCount: pendingAdds.size,
    blockHeight: currentBlock.toString(),
    // v3 샤드 상태. v2의 전역 사용률(80%/95% 임계치)에 대응하는 값이 없다 — 샤드마다
    // 독립적인 작은 트리라 전역 용량이라는 개념 자체가 없다.
    v3: {
      sessionActiveShards: shardStats.session.activeShards,
      sessionMaxShardRatio: shardStats.session.maxShardRatio,
      accountActiveShards: shardStats.account.activeShards,
      accountMaxShardRatio: shardStats.account.maxShardRatio,
      totalLeaves: shardStats.session.totalLeaves + shardStats.account.totalLeaves,
    },
  });
}));

// prepare가 확정한 회차를 IdP 상태에 반영한다.
//
// v2 시절과 순서가 뒤집혔다. v2는 prepare -> push -> commit이었고(prepare가 root를 예측할
// 수 있었으므로 그 root를 먼저 온체인에 올렸다), v3는 게시할 root가 commit 뒤에야 정해지므로
// prepare -> commit -> push다. 그래서 이 응답의 root가 곧 운영자가 push할 값이다.
//
// 중단 지점의 성격도 뒤집혔다. v2에서 push 후 commit 실패는 "체인이 앞서고 IdP가 뒤처짐"
// 이라 지갑이 받아가는 root가 온체인과 어긋나 전원이 막혔다. v3에서 commit 후 push 실패는
// "IdP가 앞서고 체인이 뒤처짐"이라, 아직 게시되지 않은 root를 지갑이 받아 쓰다가 막힌다 —
// 다음 사이클의 push가 같은 root를 올려 자동으로 수습된다. 더 나은 쪽이다.
app.post('/idp/publish/commit', requireIdPAdmin, serializeAdminMutation(async (req, res) => {
  const { roundToken } = req.body ?? {};
  if (typeof roundToken !== 'string' || roundToken.length === 0) {
    return res.status(400).json({ error: 'roundToken is required' });
  }
  if (preparedPublish === null) {
    return res.status(409).json({ error: 'no prepared publish; call POST /idp/publish/prepare first' });
  }
  if (roundToken !== preparedPublish.roundToken) {
    // 다른 회차의 토큰이다. 조용히 적용하면 운영자가 A 회차를 push했다고 믿는 동안
    // B 회차가 반영된다.
    return res.status(409).json({
      error: 'roundToken does not match the prepared publish; re-run POST /idp/publish/prepare',
    });
  }

  const prepared = preparedPublish;

  // === 만료 회수 ===
  //
  // **삽입보다 먼저 한다.** 순서가 뒤바뀌면, 게시가 지연돼 명목 만료가 지나간 폐기가
  // 트리에 들어가자마자 같은 회차에서 회수돼 사라진다 — 한 번도 효력을 갖지 못한다.
  // 회수 대상은 "이번 회차 **이전에** 이미 게시돼 있던 리프 중 만료된 것"이고, 그것이
  // 정확히 prepare가 expiredPublished로 센 집합이다. 먼저 회수하면 그 정의가 코드로
  // 성립한다. (tests/test_idp_publish_behavior.mjs 케이스 3이 이 순서를 고정한다.)
  //
  // 세션 층은 만료 축이 샤드 인덱스에 들어 있어 샤드 통째 리셋이면 되고(설계 문서 3.2절),
  // 계정 층은 값 기반 샤딩이라 샤드 단위 재기준화로 회수한다.
  let resetShards = 0;
  let acctReclaim = { leavesReclaimed: 0, shardsRebaselined: 0 };
  try {
    resetShards = revocationV3.resetExpiredSessionShards(prepared.blockHeight);
    acctReclaim = await revocationV3.rebaselineExpiredAccountShards(prepared.blockHeight);
  } catch (err) {
    // 회수 실패는 슬롯이 늦게 회수된다는 뜻일 뿐 폐기가 새는 방향이 아니다. 회차를 무르지
    // 않고 경고만 남긴다(다음 회차가 다시 시도한다) — 아래 삽입은 그대로 진행한다.
    console.error(`[IdP] publish/commit: 만료 회수 실패 — ${err.message}. 다음 회차가 재시도한다.`);
  }

  // === 준비된 폐기를 반영 ===
  //
  // 여기서 실패하면 **요청을 5xx로 되돌린다.** v2와 나란히 돌던 시절에는 그럴 수 없었다:
  // v2가 이미 append-only로 전진했고 온체인 게시도 끝난 뒤였기 때문에, 실패를 backfill
  // 플래그로 미뤄야 했다. 이제 v3가 유일한 트리이고 push는 아직 일어나지 않았으므로,
  // 실패한 회차는 그냥 실패한 회차다 — 대기열도 정리하지 않으므로 다음 prepare가 실패한
  // 리프를 자동으로 다시 집어 든다. 그 결과 v2/v3가 갈라질 수 있다는 문제와 그것을 되찾는
  // 장치(rebuild_from_v2)가 함께 사라졌다.
  let applied;
  try {
    applied = await revocationV3.applyCommit(prepared.addedValues);
  } catch (err) {
    return res.status(500).json({ error: `failed to advance the revocation forest: ${err.message}` });
  }
  if (applied.failed.length > 0) {
    // 일부만 들어간 상태다. 부분 성공을 200으로 보고하면 운영자가 그 root를 push하고
    // 빠진 폐기는 조용히 사라진다. 어느 리프가 왜 빠졌는지 남기고 실패로 돌린다.
    console.error(
      `[IdP] publish/commit: 반영하지 못한 리프 ${applied.failed.length}건 — ` +
        applied.failed.map((f) => `${f.leaf}(${f.reason})`).join(', '),
    );
    return res.status(500).json({
      error: 'some revocations could not be applied to the forest',
      failed: applied.failed,
    });
  }

  const actualRoot = revocationV3.combinedRoot();
  if (applied.sessionAdded > 0 || applied.accountAdded > 0 || resetShards > 0 || acctReclaim.leavesReclaimed > 0) {
    console.log(
      `[IdP] publish/commit: +${applied.sessionAdded} session / +${applied.accountAdded} account, ` +
        `${resetShards} expired session shard(s) reset, ${acctReclaim.leavesReclaimed} account ` +
        `leaf/leaves reclaimed in ${acctReclaim.shardsRebaselined} shard(s), root ${actualRoot}`,
    );
  }

  const committed = new Set(publishedLeaves());

  // 대기열 정리: 이번에 반영된 것과, prepare 시점에 이미 만료라 버려진 것을 뺀다.
  // prepare 이후에 새로 들어온 폐기는 남겨서 다음 회차로 넘긴다.
  for (const leafKey of [...pendingAdds]) {
    if (committed.has(leafKey)) {
      pendingAdds.delete(leafKey);
      continue;
    }
    const expiryBlock = leafExpiry.get(leafKey);
    if (expiryBlock !== undefined && expiryBlock <= prepared.blockHeight) pendingAdds.delete(leafKey);
  }
  // 만료 메타데이터 정리: 게시 집합에도 대기열에도 없는 리프는 고아다.
  for (const leafKey of [...leafExpiry.keys()]) {
    if (!committed.has(leafKey) && !pendingAdds.has(leafKey)) leafExpiry.delete(leafKey);
  }

  // v3 쪽 메타데이터(layer/sessionMaxHeight/accountExpiry)도 같은 자리에서 정리한다.
  // 게시되지 않은 접수분은 어떤 회수 경로도 건드리지 않아 영구 누적됐고, 이 맵들은
  // saveIdPState에 실려 로그인마다 다시 쓰인다(2026-09-06 2차 리뷰).
  //
  // **반드시 위 대기열 정리 뒤에** 호출한다. 아직 대기 중인 리프의 층 기록이 먼저
  // 사라지면 다음 commit이 그 리프를 실패로 처리한다. 위에서 만료된 대기분이 이미
  // 제거됐으므로, 여기서 만료 기준으로 지우는 것은 안전하다.
  const prunedV3Meta = revocationV3.pruneExpiredMetadata(prepared.blockHeight);
  if (prunedV3Meta > 0) {
    console.log(`[IdP] publish/commit: v3 만료 메타데이터 ${prunedV3Meta}건 정리`);
  }

  // issuanceLog/auidILog 축출: 로그인마다 쌓이기만 하고 절대 줄지 않으면(무제한 성장)
  // 매 로그인의 상태 파일 재작성 비용도 시간이 갈수록 커진다. 이미 현재 블록을 아는
  // 이 게시 경로에서 함께 정리하는 게 자연스럽다(요청마다 별도로 블록 높이를 다시
  // 조회할 필요가 없다).
  //
  // 기준은 반드시 만료(maxHeight) 기반이어야 한다 — 개수 상한이나 나이(LRU/TTL)
  // 기준을 쓰면 아직 살아있는 r_token이 usedNonces의 seed 대상(issuanceLog)에서
  // 빠져 재전송이 다시 열린다. 다만 만료(maxHeight <= currentBlock) 즉시 축출하면
  // /idp/revoke가 최근 만료 세션에 내는 410 Gone이 404("발급된 적 없음")로 바뀌어
  // 버리는 의미가 사라진다. 그래서 만료 후에도 CREDENTIAL_LIFETIME_BLOCKS만큼 더
  // 여유를 두고서야 축출한다 — 최근 만료분은 여전히 410을, 그보다 오래된 것만 404를
  // 받는다.
  //
  // usedNonces는 여기서 절대 건드리지 않는다 — 이 프로세스가 사는 동안 재전송 방지가
  // 줄어들면 안 되기 때문이다(이 r_token으로 두 번째 statement를 받을 수 있다는 뜻이
  // 되므로).
  //
  // 다만 재시작을 넘어서는 영구적이지 않다는 점을 분명히 해 둔다: usedNonces는
  // 영속화되지 않는 인메모리 Set이고, 기동 시 issuanceLog의 키로만 seed된다. 발급
  // 시점의 add는 이 프로세스 안에서만 유효하다. 따라서 여기서 축출된 r_token은 다음
  // 재시작 후 재전송 방지 대상에서 빠진다 — 축출 기준이 만료 + CREDENTIAL_LIFETIME_BLOCKS
  // 이라 그때 그 크레덴셜은 이미 온체인에서 만료라(max_height 초과) 재발급받아도
  // 쓸 수 없다는 것이 이 축출을 허용하는 근거다. 축출 기준을 만료 무관하게 바꾸면
  // (개수 상한·LRU/TTL) 이 근거가 무너진다.
  const evictionCutoff = prepared.blockHeight;
  let evictedIssuance = 0;
  for (const [rToken, entry] of [...issuanceLog]) {
    if (BigInt(entry.maxHeight) + CREDENTIAL_LIFETIME_BLOCKS < evictionCutoff) {
      issuanceLog.delete(rToken);
      evictedIssuance += 1;
    }
  }
  let evictedAuidI = 0;
  for (const [auidI, entry] of [...auidILog]) {
    if (BigInt(entry.maxHeight) + CREDENTIAL_LIFETIME_BLOCKS < evictionCutoff) {
      auidILog.delete(auidI);
      evictedAuidI += 1;
    }
  }
  if (evictedIssuance > 0 || evictedAuidI > 0) {
    console.log(
      `[IdP] publish/commit: evicted ${evictedIssuance} issuanceLog record(s) and ` +
        `${evictedAuidI} auidILog record(s) whose maxHeight + CREDENTIAL_LIFETIME_BLOCKS ` +
        `(${CREDENTIAL_LIFETIME_BLOCKS}) is behind block ${evictionCutoff}`,
    );
  }

  preparedPublish = null;

  // 게시된 트리·만료·대기열이 한꺼번에 바뀌었다. 여기서 저장하지 않으면 재시작
  // 후 IdP가 옛 root를 서빙해 온체인에 게시된 root와 어긋난다 — 그러면 폐기된
  // 사용자가 아니라 **전원**의 execute()가 StaleRevocationRoot로 막히고, 방금 게시한
  // 폐기는 조용히 풀린다.
  //
  // 그런데 여기서 5xx를 낼 수는 없다: 포레스트는 이미 전진했고 preparedPublish도 비워져
  // 커밋을 재시도할 방법이 없다(재시도는 409다). 전진 자체는 성공했으므로 발급 경로와 같은
  // 선례를 따른다 — 200으로 보고하되 저장 실패를 응답에 구조적으로 실어 운영자가 알아채게
  // 한다. 성공 시(대다수)에는 필드를 넣지 않아 응답 모양이 그대로다.
  //
  // 이 경로에서는 **push하지 않는 것이 옳다.** 저장되지 않은 root를 온체인에 올리면
  // 재시작 후 IdP가 옛 root를 서빙해 전원이 막힌다. sweep은 persistenceWarning을 받으면
  // push 없이 중단한다.
  const persisted = saveIdPState();
  const persistenceWarning = persisted
    ? undefined
    : 'the published state could not be persisted; after an IdP restart this IdP would serve the ' +
      'pre-commit root while the chain holds the new one, blocking every wallet with ' +
      'StaleRevocationRoot. Recover the state file and re-publish before restarting.';
  if (!persisted) {
    console.error(
      `[IdP] publish/commit: FAILED TO PERSIST the published state (root ${actualRoot}). ` +
        'Do not push this root and do not restart this IdP until the state file is recovered.',
    );
  }

  const publishedCount = publishedLeaves().length;
  console.log(
    `[IdP] publish/commit: published ${publishedCount} leaves, root ${actualRoot}, ` +
      `pending ${pendingAdds.size}`,
  );
  res.json({
    root: actualRoot,
    leafCount: publishedCount,
    pendingCount: pendingAdds.size,
    ...(persistenceWarning ? { persistenceWarning } : {}),
  });
}));

// --- 계정 층(사람 차단) 관리자 엔드포인트 ---
//
// 폐기 트리(위 /idp/revoke, /idp/publish/*)는 "이미 발급된 크레덴셜의 회수"만 한다 —
// 가역이고, 어차피 만료되면(트리 수명 관리) 풀린다. "이 사람의 앞으로의 로그인을
// 막는다"는 트리가 할 수 없는 일이라 계정 층에서 처리한다(docs/REVOCATION_FOLLOWUPS.md
// 0절). 인증은 /idp/revoke·/idp/publish/*와 동일한 requireIdPAdmin이다 — 조회
// (requireIdPAuditor)가 아니라 폐기와 같은 등급의 관리 조작이기 때문이다.

// 계정 비활성화/재활성화를 하나의 엔드포인트로 묶는다(/idp/revoke가 type으로 session/
// account를 가르는 것과 같은 방식). disabled 값 자체를 요청자가 지정하게 해 멱등하게
// 만든다 — "다시 켜기"를 별도 엔드포인트로 만들 이유가 없다.
app.post('/idp/account/set_disabled', requireIdPAdmin, async (req, res) => {
  const { username, disabled } = req.body ?? {};
  if (typeof username !== 'string' || username.length === 0) {
    return res.status(400).json({ error: 'username is required' });
  }
  if (typeof disabled !== 'boolean') {
    return res.status(400).json({ error: 'disabled must be a boolean' });
  }
  const user = users[username];
  if (!user) {
    return res.status(404).json({ error: `no such account: ${username}` });
  }

  const previous = user.disabled;
  user.disabled = disabled;

  // disabled는 보안 상태라 저장 실패를 조용히 넘기면 안 된다(다른 관리 조작과 동일한
  // 정책 — /idp/revoke 참고). 실패하면 이번 요청의 변경만 롤백하고 5xx로 응답한다.
  const saved = saveIdPState();
  if (!saved) {
    user.disabled = previous;
    return res.status(500).json({
      error: 'failed to persist disabled flag; the change was not recorded, please retry',
    });
  }

  console.log(`[IdP] account "${username}": disabled ${previous} -> ${disabled}`);
  res.json({ username, disabled });
});

// 재바인딩 복구(고정 해제). pinAuidToAccount 자체는 그대로 둔다 — 지갑이 일방적으로
// 새 salt를 들이미는 것은 계속 거부해야 하고, 여기서 하는 일은 그 저지선을 지운 채로
// 다음 로그인 한 번을 "첫 로그인"처럼 다시 받아주는 것뿐이다(user.lastAuid = null).
// 해제 여부의 판단 주체는 IdP(운영자)여야 한다는 것이 이 엔드포인트의 요점이다.
app.post('/idp/account/unpin_auid', requireIdPAdmin, async (req, res) => {
  const { username } = req.body ?? {};
  if (typeof username !== 'string' || username.length === 0) {
    return res.status(400).json({ error: 'username is required' });
  }
  const user = users[username];
  if (!user) {
    return res.status(404).json({ error: `no such account: ${username}` });
  }
  // disabled 계정에는 재바인딩 복구를 거부한다. 안 그러면 부정 사용으로 차단한 계정이
  // 이 복구 흐름으로 되살아난다 — 부정 사용은 disabled로, 키 분실은 unpin_auid로,
  // 두 도구의 역할을 갈라 둔다(docs/REVOCATION_FOLLOWUPS.md 참고). 이미 disabled인
  // 계정을 되살리려는 시도는 먼저 set_disabled로 재활성화부터 해야 한다.
  if (user.disabled) {
    return res.status(409).json({
      error: 'account is disabled; unpin is refused for disabled accounts (re-enable via ' +
        'POST /idp/account/set_disabled first if that is actually intended)',
    });
  }

  const previousAuid = user.lastAuid;
  user.lastAuid = null;

  const saved = saveIdPState();
  if (!saved) {
    user.lastAuid = previousAuid;
    return res.status(500).json({
      error: 'failed to persist unpin; the account was not unpinned, please retry',
    });
  }

  // 운영 가시성: 이 계정이 (옛 auid에 대한) 계정 폐기 리프를 트리에 갖고 있다면 알려준다.
  // 해제 자체는 그래도 허용된다 — 새 salt -> 새 auid -> 새 PPID라 옛 리프가 새 로그인을
  // 막지 못한다(리프는 Poseidon(TAG_ACCOUNT, 옛 auid)라서 새 auid와 값이 다르다). 다만
  // 운영자가 "이 계정을 폐기해뒀었는데 방금 그 봉인을 풀었다"는 사실은 알아야 한다.
  let staleRevocationLeaf = null;
  if (previousAuid !== null) {
    try {
      const leaf = (await leafValue(TAG_ACCOUNT, String(previousAuid))).toString();
      const published = await revocationV3.hasLeaf(leaf);
      const pending = pendingAdds.has(leaf);
      if (published || pending) {
        staleRevocationLeaf = { leaf, published, pending };
      }
    } catch {
      // leafValue가 옛 auid를 거부해도(형식 이상 등) unpin 자체는 이미 끝났다 — 이
      // 안내는 부가 정보일 뿐이라 실패해도 응답을 막지 않는다.
    }
  }

  console.log(
    `[IdP] account "${username}": unpinned auid (was ${previousAuid ?? '(none)'})` +
      (staleRevocationLeaf
        ? `; NOTE: this account still carries an account-level revocation leaf for its old auid ` +
          `(published=${staleRevocationLeaf.published}, pending=${staleRevocationLeaf.pending}) — ` +
          'it no longer blocks this account once it logs in again with a new salt'
        : ''),
  );

  res.json({
    username,
    previousAuid,
    ...(staleRevocationLeaf ? { staleRevocationLeaf } : {}),
  });
});

// === v3(이중 트리) 조회 — 지갑이 자기 샤드 두 개만 받아가는 경로 ===
//
// v2 조회와 근본적으로 다른 점: **증분 동기화 프로토콜이 없다.** 서브트리 하나가 최대
// 256~1,024리프라 지갑이 자기 샤드를 통째로 받아도 싸기 때문이다. 그래서 seq·epoch·
// 변경 로그·tooOld가 전부 사라진다(설계 문서의 실질적 이득 중 하나).
//
// 루트 목록도 통째로 보내지 않는다. 샤드가 4,096 + 256개라 전부 보내면 수백 KB가 되므로,
// 빈 서브트리 상수 하나와 **비어 있지 않은 샤드의 덮어쓰기 목록**만 보낸다. 폐기가
// 드물다는 전제에서 응답이 사실상 상수 크기다.
//
// 쿼리로 sessionShard/accountShard를 주면 그 샤드의 리프 배열과 상위 형제까지 함께 준다.
// 주지 않으면 루트 정보만 준다.
//
// 주의: 여기서 서빙하는 것은 **게시된 상태**다(v2와 같은 규칙). 대기 중인 pendingAdds는
// 들어 있지 않다 — 넣으면 지갑이 온체인에 없는 root로 witness를 만들게 된다.
app.get('/idp/revocation_state_v3', (req, res) => {
  const parseShard = (raw, label, bound) => {
    if (raw === undefined) return undefined;
    if (!/^[0-9]+$/.test(String(raw))) throw new Error(`${label} must be a non-negative integer`);
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 0 || n >= bound) throw new Error(`${label} out of range [0, ${bound})`);
    return n;
  };
  let sessionShard;
  let accountShard;
  try {
    sessionShard = parseShard(req.query.sessionShard, 'sessionShard', SESSION_SHARD_COUNT);
    accountShard = parseShard(req.query.accountShard, 'accountShard', ACCOUNT_SHARD_COUNT);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  res.json(revocationV3.snapshot({ sessionShard, accountShard }));
});

// 4. Public Keys Endpoint (for RP verification)
app.get('/ps_public_keys', (req, res) => {
  res.json({
    g2: psParams.g2.getStr(16),
    X: idpKeys.pk.X.getStr(16),
    Y: idpKeys.pk.Y.map(y => y.getStr(16)),
    pk_IdP: [
      eddsa.F.toObject(idpEdDSAKeys.pub[0]).toString(),
      eddsa.F.toObject(idpEdDSAKeys.pub[1]).toString(),
    ],
  });
});

// 초기화를 listen '전에' 끝낸다. 예전에는 listen 콜백 안에서 돌렸는데, 그러면 (1) 키가
// 준비되기 전에 이미 포트가 열려 초기 요청이 null 키를 만질 수 있고, (2) 손상된 키 파일을
// 만났을 때 콜백 안의 throw가 unhandled rejection으로 흘러 서버가 '깨진 채로 살아있게'
// 된다. 최상위 await로 올리면 초기화 실패가 곧바로 기동 중단이 된다.
await initKeys();
await snarkjs.curves.getCurveFromName('bn128'); // bn128 WASM 모듈 미리 빌드 (첫 pi_i 검증 지연 방지)

const server = app.listen(PORT, () => {
  console.log(`Custom IdP running at http://localhost:${PORT}`);
  if (!IDP_ADMIN_SECRET) {
    // 값은 절대 출력하지 않고, 설정 여부만 알린다.
    console.warn('[IdP] IDP_ADMIN_SECRET is not set — POST /idp/revoke will return 503 until it is configured.');
  }
  if (!IDP_AUDITOR_SECRET) {
    console.warn('[IdP] IDP_AUDITOR_SECRET is not set — B2 trace endpoints (lookup_uid_by_r_token/auid_i) will return 503 until it is configured.');
  }
});
