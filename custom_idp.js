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
import { createIMT, leafValue, TAG_SESSION, TAG_ACCOUNT } from './lib/imt.js';

const app = express();
const PORT = 4000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// VKey 로드
const vkeyAridI = JSON.parse(fs.readFileSync('build/mode2/pi_arid_i_vkey.json', 'utf8'));

// 폐기 트리. 아래 상태들은 idp_state.json에 영속화되어 재시작을 넘어 살아남는다
// (issuanceLog/auidILog/users[*].lastAuid도 함께 — 파일 하단의 영속화 절 참고).
//
// == 게시된 상태와 대기 상태의 분리 (배칭) ==
// revocationTree/revokedLeaves는 '마지막으로 온체인에 게시된' 폐기 상태다.
// /idp/revocation_state는 이것만 서빙한다. 폐기 요청은 즉시 트리에 들어가지 않고
// pendingAdds에 쌓였다가 /idp/publish/prepare + /idp/publish/commit 때 한꺼번에
// 반영된다.
//
// 왜 즉시 반영하면 안 되는가: 지갑은 /idp/revocation_state로 트리를 재구성해
// witness를 만드는데, 그 root가 RevocationRegistry에 게시돼 있지 않으면 온체인
// execute()가 StaleRevocationRoot로 revert한다. 폐기 즉시 IdP 상태만 전진하면
// 게시 전까지 '정상 사용자 전원'이 막힌다. 게시될 때까지 옛(=게시된) 상태를 계속
// 서빙하면 그 장애 창이 사라지고, 폐기 효력 지연은 게시 주기만큼으로 유계가 된다.
const REVOCATION_TREE_DEPTH = 20;
let revocationTree = await createIMT(REVOCATION_TREE_DEPTH);
let revokedLeaves = [];
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
// 리프별 만료 블록. lib/imt.js는 트리만 알아야 하므로, 만료 메타데이터(leaf 문자열 ->
// expiryBlock BigInt)는 revokedLeaves와 나란히 IdP가 따로 관리한다. 게시분과 대기분을
// 함께 담는다. commit이 이 맵과 revocationTree, revokedLeaves 셋을 항상 함께 갱신해야
// 한다 — 어긋나면 지갑이 revokedLeaves로 재구성한 root가 IdP root와 달라져 전원 실패한다.
const leafExpiry = new Map();

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
const IDP_KEY_FILE = path.join(__dirname, 'idp_keys.json');
const IDP_KEY_FILE_VERSION = 1;

// 개발용 강제 회전 스위치. 설정하면 기존 키 파일을 무시하고 새 키를 생성해 덮어쓴다.
// 회전 후에는 server.js 재시작 → PPIDWalletFactory 재배포 → wallet_agent.js 재시작이
// 필요하다(README.md 참고).
const IDP_ROTATE_KEYS = Boolean(process.env.IDP_ROTATE_KEYS);

// wallet_agent.js:361의 선례를 그대로 따른다 — 시크릿 파일은 소유자만 읽고 쓸 수 있게 한다.
function writeSecretFile(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2), { mode: 0o600 });
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // best-effort; writeFileSync의 mode가 일반적인 경우를 이미 덮는다.
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
const users = {
  'testuser': { password: 'password123', uid: '12345', sub: '12345', lastAuid: null },
  'alice': { password: 'secret456', uid: '67890', sub: '67890', lastAuid: null }
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
const IDP_STATE_FILE = path.join(__dirname, 'idp_state.json');
const IDP_STATE_FILE_VERSION = 1;

function stateFileError(detail) {
  return new Error(
    `[CustomIdP] IdP state file ${IDP_STATE_FILE} is unusable (${detail}). ` +
    'Refusing to start with a silently wrong revocation state: if the published root does not ' +
    'match what wallets rebuild from /idp/revocation_state, every wallet transaction fails. ' +
    `Inspect the file, or remove it to start from empty state (pending/published revocations, ` +
    'issuance records, and auid pinning would then be lost).',
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
    // 로드 시 재구성한 트리의 root가 저장 시점과 같은지 대조하는 기준값.
    // 이게 없으면 리프 목록이 조용히 어긋나도 알아챌 방법이 없다.
    publishedRoot: revocationTree.getRoot().toString(),
    revokedLeaves,
    pendingAdds: [...pendingAdds],
    leafExpiry: Object.fromEntries([...leafExpiry].map(([k, v]) => [k, v.toString()])),
    issuanceLog: Object.fromEntries(
      [...issuanceLog].map(([k, v]) => [k, { uid: String(v.uid), maxHeight: String(v.maxHeight) }]),
    ),
    auidILog: Object.fromEntries([...auidILog].map(([k, v]) => [k, String(v)])),
    // users에서 영속화하는 것은 lastAuid뿐이다. username/password/uid는 소스에 있는
    // 데모 상수라 저장할 이유가 없고, 저장하면 비밀번호가 파일로 새어나간다.
    lastAuid: Object.fromEntries(Object.entries(users).map(([name, u]) => [name, u.lastAuid])),
  };
}

// 상태가 바뀔 때마다 호출한다.
// 저장에 실패해도 요청을 실패시키지는 않는다 — 인메모리 상태는 이미 정확하고 요청 자체는
// 성공했기 때문이다. 다만 그 변경은 다음 재시작 때 사라지므로 운영자가 반드시 알아야 한다.
// 조용히 삼키지 않고 명확히 에러 로그를 남긴다.
function saveIdPState() {
  try {
    writeSecretFile(IDP_STATE_FILE, serializeIdPState());
  } catch (err) {
    console.error(
      `[IdP] FAILED to persist state to ${IDP_STATE_FILE}: ${err.message} — ` +
      'this change will be lost on restart',
    );
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

  if (parsed?.version !== IDP_STATE_FILE_VERSION) throw stateFileError('unsupported version');
  if (!Array.isArray(parsed.revokedLeaves)) throw stateFileError('revokedLeaves must be an array');
  if (!Array.isArray(parsed.pendingAdds)) throw stateFileError('pendingAdds must be an array');
  for (const key of ['leafExpiry', 'issuanceLog', 'auidILog', 'lastAuid']) {
    if (!isPlainObject(parsed[key])) throw stateFileError(`${key} must be an object`);
  }
  if (typeof parsed.publishedRoot !== 'string') throw stateFileError('publishedRoot must be a string');

  const leaves = parsed.revokedLeaves.map((l, i) => assertDecimalString(l, `revokedLeaves[${i}]`));

  // 게시 트리는 lib/imt.js를 그대로 쓰고, 저장된 리프로 insert()를 반복해 재구성한다.
  const tree = await createIMT(REVOCATION_TREE_DEPTH);
  for (const leafKey of leaves) await tree.insert(BigInt(leafKey));
  const rebuiltRoot = tree.getRoot().toString();

  // 재구성한 root가 저장 시점과 다르면 조용히 넘어가면 안 된다 — 지갑이
  // /idp/revocation_state의 리프로 만든 root와 IdP가 믿는 root가 어긋나 전원이 실패한다.
  // root는 이미 공개 엔드포인트로 나가는 값이라 로그에 남겨도 무방하다.
  if (rebuiltRoot !== parsed.publishedRoot) {
    throw stateFileError(
      `rebuilt root ${rebuiltRoot} does not match the saved root ${parsed.publishedRoot}`,
    );
  }

  revocationTree = tree;
  revokedLeaves = leaves;

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

  auidILog.clear();
  for (const [auidI, uid] of Object.entries(parsed.auidILog)) {
    auidILog.set(auidI, String(uid));
  }

  // 소스에 존재하는 데모 계정에만 복원한다. 파일에 모르는 이름이 들어있어도 계정을
  // 새로 만들지 않는다 — 상태 파일이 계정 생성 경로가 되어서는 안 된다.
  for (const [name, lastAuid] of Object.entries(parsed.lastAuid)) {
    if (!Object.prototype.hasOwnProperty.call(users, name)) continue;
    users[name].lastAuid = lastAuid === null ? null : String(lastAuid);
  }

  console.log(
    `[CustomIdP] Loaded state from ${IDP_STATE_FILE}: ${revokedLeaves.length} published leaves ` +
    `(root ${rebuiltRoot}), ${pendingAdds.size} pending, ${issuanceLog.size} issuance records`,
  );
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
const PAR_REQUEST_TTL_MS = 60 * 1000;
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
  if (!state || !nonce) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'state and nonce are required' });
  }
  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'code_challenge (S256) is required' });
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
  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  try {
    const verifySignals = [user.uid.toString(), ...record.zkpPublicSignals];
    assertDecimalSignals(verifySignals, 8, 'pi_i');
    const isValid = await snarkjs.groth16.verify(vkeyAridI, verifySignals, record.zkpProof);
    if (!isValid) throw new Error('Identity Mismatch: This proof was not made for you!');

    const idpPubX = eddsa.F.toObject(idpEdDSAKeys.pub[0]).toString();
    const idpPubY = eddsa.F.toObject(idpEdDSAKeys.pub[1]).toString();
    if (String(verifySignals[6]) !== idpPubX || String(verifySignals[7]) !== idpPubY) {
      throw new Error('pi_i was proven against a different IdP key');
    }

    pinAuidToAccount(user, verifySignals[5]);

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
  if (!code || !code_verifier || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'code, code_verifier, and redirect_uri are required' });
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
  issuanceLog.set(String(record.token_nonce), { uid: record.uid, maxHeight: record.max_height });
  auidILog.set(String(record.auid_i), record.uid);
  // 발급 기록은 /idp/revoke의 입구 검사가 조회하는 대상이라 반드시 살아남아야 한다.
  saveIdPState();

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

  const idpToken = {
    arid_i: business.arid_i,
    auid_i: business.auid_i,
    r_token: rToken.toString(),
    max_height: maxHeight.toString(),
    chain_id: chainId.toString(),
    exp: exp,
    signature: sigJson
  };
  // maxHeight는 이 함수 위쪽에서 business.maxHeight ?? business.max_height로 이미
  // 채워진 지역 변수다(줄 658 부근).
  issuanceLog.set(rToken.toString(), { uid: user.uid, maxHeight: maxHeight.toString() });
  auidILog.set(String(business.auid_i), user.uid);
  // 발급 기록은 /idp/revoke의 입구 검사가 조회하는 대상이라 반드시 살아남아야 한다.
  saveIdPState();
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
app.post('/idp/lookup_uid_by_r_token', (req, res) => {
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
app.post('/idp/lookup_uid_by_auid_i', (req, res) => {
  const { auid_i } = req.body ?? {};
  if (!auid_i) {
    return res.status(400).json({ error: 'auid_i is required' });
  }
  const uid = auidILog.get(String(auid_i));
  if (uid === undefined) {
    return res.status(404).json({ error: 'No issuance record found for this auid_i' });
  }
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

// 폐기 대상 등록. type='session'이면 r_token, 'account'면 auid를 값으로 받는다.
// 어느 쪽이든 IdP가 이미 알고 있는 값이다(issuanceLog / user.lastAuid).
app.post('/idp/revoke', requireIdPAdmin, async (req, res) => {
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
    // 계정 폐기는 항상 통과한다. 폐기 직전에 발급된 크레덴셜(만료가 최대
    // 발급시각 + CREDENTIAL_LIFETIME_BLOCKS)까지 덮어야 하므로 만료 블록은
    // 현재 블록 + 크레덴셜 수명이다.
    expiryBlock = currentBlock + CREDENTIAL_LIFETIME_BLOCKS;
  }

  try {
    const leaf = await leafValue(tag, valueStr);
    const leafKey = leaf.toString();

    // 게시 트리는 여기서 건드리지 않는다. 대기열에만 넣고, 실제 반영은
    // /idp/publish/prepare + /idp/publish/commit이 한다.
    const alreadyPublished = revokedLeaves.includes(leafKey);
    const alreadyPending = pendingAdds.has(leafKey);
    if (!alreadyPublished && !alreadyPending) pendingAdds.add(leafKey);

    // 재폐기는 에러가 아니라 no-op이다. 다만 계정 재폐기는 폐기 창을 연장해야
    // 하므로(새로 발급된 크레덴셜까지 덮어야 한다) 만료 블록은 더 늦은 쪽으로
    // 갱신한다. 짧은 쪽으로 덮어쓰면 창이 줄어 폐기가 조기에 풀린다.
    const previousExpiry = leafExpiry.get(leafKey);
    const effectiveExpiry =
      previousExpiry !== undefined && previousExpiry > expiryBlock ? previousExpiry : expiryBlock;
    leafExpiry.set(leafKey, effectiveExpiry);

    // 대기열과 만료 메타데이터가 재시작을 넘어 살아남아야 접수된 폐기가 사라지지 않는다.
    saveIdPState();

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
});

// 관리자 전용 게시 엔드포인트 (prepare/commit 2단계).
//
// 왜 한 번에 하지 않는가: "IdP는 전진했는데 온체인 push는 실패" 상태가 생기면 지금
// 고치려는 문제(게시되지 않은 root로 witness를 만들어 전원이 막힘)가 그대로 재발한다.
// push가 확정된 뒤에만 IdP가 전진하도록 순서를 강제한다.
//   prepare 후 push 실패 -> 아무것도 안 바뀜(안전)
//   push 후 commit 실패  -> 체인이 더 최신. 지갑은 옛 root를 쓰고 그건 아직
//                           GRACE_BLOCKS 안이라 동작한다(안전한 방향)
//
// 만료 리프 제거(sweep)도 이 경로에 흡수됐다. 만료된 리프를 빼야 지갑의 매 트랜잭션
// 재구성 비용이 무한정 늘지 않는다(docs/REVOCATION_FOLLOWUPS.md 0절).
// 인증은 /idp/revoke와 동일한 requireIdPAdmin을 재사용한다.
app.post('/idp/publish/prepare', requireIdPAdmin, async (req, res) => {
  let currentBlock;
  try {
    currentBlock = await getCurrentBlockHeight();
  } catch (err) {
    return res.status(502).json({ error: `failed to read current block height: ${err.message}` });
  }

  // 다음 게시 집합 = (게시된 리프 ∪ 대기 리프) − (만료된 것)
  const candidate = [];
  for (const leafKey of [...revokedLeaves, ...pendingAdds]) {
    if (candidate.includes(leafKey)) continue;
    const expiryBlock = leafExpiry.get(leafKey);
    // 만료 정보가 없는 리프는 조용히 버리지 않고 남긴다. 버리면 폐기가 소리 없이
    // 풀리는 fail-open이 된다.
    if (expiryBlock !== undefined && expiryBlock <= currentBlock) continue;
    candidate.push(leafKey);
  }

  // 임시 트리로만 계산한다. 게시 트리는 commit 전까지 절대 건드리지 않는다.
  let expectedRoot;
  try {
    const preview = await createIMT(REVOCATION_TREE_DEPTH);
    for (const leafKey of candidate) await preview.insert(BigInt(leafKey));
    expectedRoot = preview.getRoot().toString();
  } catch (err) {
    return res.status(500).json({ error: `failed to compute prepared root: ${err.message}` });
  }

  const candidateSet = new Set(candidate);
  const publishedSet = new Set(revokedLeaves);
  const added = candidate.filter((k) => !publishedSet.has(k)).length;
  const removed = revokedLeaves.filter((k) => !candidateSet.has(k)).length;

  // 여러 번 호출하면 마지막 것이 유효하다. prepare와 commit 사이에 들어온 폐기는
  // 이번 회차에 포함되지 않고 다음 회차로 넘어간다 — 의도된 동작이다.
  preparedPublish = { root: expectedRoot, leaves: candidate, blockHeight: currentBlock };

  const currentRoot = revocationTree.getRoot().toString();
  console.log(
    `[IdP] publish/prepare at block ${currentBlock}: +${added} -${removed}, ` +
      `leaves ${revokedLeaves.length} -> ${candidate.length}, expectedRoot ${expectedRoot}`,
  );
  // 추가·제거가 0건이어도 200이다 — 그 경우가 heartbeat다(같은 root를 재게시해
  // RevocationRegistry의 GRACE_BLOCKS 만료로 정상 사용자가 막히는 것을 막는다).
  res.json({
    expectedRoot,
    currentRoot,
    added,
    removed,
    leafCount: candidate.length,
    pendingCount: pendingAdds.size,
    blockHeight: currentBlock.toString(),
  });
});

// prepare가 계산한 root가 온체인에 실제로 게시된 뒤에만 호출돼야 한다.
app.post('/idp/publish/commit', requireIdPAdmin, async (req, res) => {
  const { root } = req.body ?? {};
  if (root === undefined || root === null) {
    return res.status(400).json({ error: 'root is required' });
  }
  if (preparedPublish === null) {
    return res.status(409).json({ error: 'no prepared publish; call POST /idp/publish/prepare first' });
  }
  if (String(root).trim() !== preparedPublish.root) {
    // 그 사이 상태가 바뀌었거나 다른 회차의 root다. 조용히 적용하면 게시된 온체인
    // root와 IdP 상태가 어긋난다.
    return res.status(409).json({
      error: 'root does not match the prepared publish; re-run POST /idp/publish/prepare',
      expectedRoot: preparedPublish.root,
    });
  }

  const prepared = preparedPublish;

  // 게시 트리를 준비된 리프 집합으로 통째로 교체한다.
  let nextTree;
  let actualRoot;
  try {
    nextTree = await createIMT(REVOCATION_TREE_DEPTH);
    for (const leafKey of prepared.leaves) await nextTree.insert(BigInt(leafKey));
    actualRoot = nextTree.getRoot().toString();
  } catch (err) {
    return res.status(500).json({ error: `failed to rebuild the published tree: ${err.message}` });
  }

  // 세 상태(revocationTree, revokedLeaves, leafExpiry)가 어긋나면 지갑이
  // revokedLeaves로 재구성한 root가 IdP root와 달라져 모든 지갑이 실패한다.
  // 조용히 넘어가지 않고 명확히 거부하고, 게시 상태는 그대로 둔다.
  if (actualRoot !== prepared.root) {
    console.error(
      `[IdP] publish/commit aborted: rebuilt root ${actualRoot} != prepared root ${prepared.root}`,
    );
    return res.status(500).json({
      error: 'rebuilt tree root does not match the prepared root; published state left unchanged',
      preparedRoot: prepared.root,
      rebuiltRoot: actualRoot,
    });
  }

  revocationTree = nextTree;
  revokedLeaves = [...prepared.leaves];

  const committed = new Set(prepared.leaves);
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

  preparedPublish = null;

  // 게시된 트리·리프·만료·대기열이 한꺼번에 바뀌었다. 여기서 저장하지 않으면 재시작
  // 후 IdP가 옛 root를 서빙해 온체인에 게시된 root와 어긋난다.
  saveIdPState();

  console.log(
    `[IdP] publish/commit: published ${revokedLeaves.length} leaves, root ${actualRoot}, ` +
      `pending ${pendingAdds.size}`,
  );
  res.json({ root: actualRoot, leafCount: revokedLeaves.length, pendingCount: pendingAdds.size });
});

// 지갑이 자기 witness를 계산하려면 폐기 목록 전체가 필요하다.
// 리프는 Poseidon 해시라 preimage가 드러나지 않으므로 공개해도 안전하다.
//
// **마지막으로 게시된 상태만** 서빙한다. 대기 중인 폐기(pendingAdds)는 여기 넣지
// 않는다 — 넣으면 지갑이 온체인에 없는 root로 witness를 만들어 전원이 막힌다.
// 응답 형태 { root, revokedLeaves }는 wallet_agent.js와의 계약이라 바뀌지 않는다.
// 대기 현황은 관리자 전용 prepare/commit 응답과 로그로만 노출한다.
app.get('/idp/revocation_state', (req, res) => {
  res.json({ root: revocationTree.getRoot().toString(), revokedLeaves });
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
});
