// custom_idp.js는 모듈 최상위 부수효과(포트 바인딩, RPC 접근, 실제 idp_keys.json/
// idp_state.json 파일 읽기·쓰기)가 있어서 안전하게 import할 수 없다. tests/
// test_uid_wallet_boundary.js의 선례를 따라 소스를 텍스트로 읽어 정규식으로 검사한다.
// 이 방식은 "그 자리에 있어야 할 코드가 실제로 있는지"(구조적 회귀)만 잡는다 — 런타임
// 동작(원자적 쓰기가 실제로 원자적인지, 재전송이 실제로 막히는지 등)은 이 테스트가 아니라
// .superpowers/sdd/persistence-fix-report.md에 기록한 수동 검증(실제 IdP 재시작 +
// HTTP 요청)으로 확인했다. 못 덮는 이유는 같은 문서에 적었다.
import assert from 'node:assert/strict';
import fs from 'node:fs';

const src = fs.readFileSync('custom_idp.js', 'utf8');

function section(startMarker, endMarker, label) {
  const start = src.indexOf(startMarker);
  assert(start !== -1, `could not find start marker for ${label}: ${startMarker}`);
  const end = src.indexOf(endMarker, start);
  assert(end !== -1, `could not find end marker for ${label}: ${endMarker}`);
  return src.slice(start, end);
}

// ---------------------------------------------------------------------------
// 1. writeSecretFile은 임시 파일 + rename으로 원자적으로 쓴다.
// ---------------------------------------------------------------------------
const writeSecretFileSrc = section('function writeSecretFile(file, obj) {', '\nfunction ', 'writeSecretFile');

assert.match(
  writeSecretFileSrc,
  /openSync\(tmpFile,\s*'w',\s*0o600\)/,
  'writeSecretFile must create the temp file with mode 0o600 from the moment it exists',
);
assert.match(
  writeSecretFileSrc,
  /fs\.renameSync\(tmpFile,\s*file\)/,
  'writeSecretFile must publish via rename (atomic on the same filesystem), not writeFileSync(file, ...) directly',
);
assert.doesNotMatch(
  writeSecretFileSrc,
  /fs\.writeFileSync\(file,/,
  'writeSecretFile must not write directly to the target path (that reintroduces the torn-write window)',
);
assert.match(
  writeSecretFileSrc,
  /unlinkSync\(tmpFile\)/,
  'writeSecretFile must clean up the temp file if the write or rename fails',
);

// ---------------------------------------------------------------------------
// 2. stateFileError는 "지우면 된다"를 권하지 않고, 지웠을 때의 결과(전원 차단 후
//    fail-open 재게시)를 명시한다.
// ---------------------------------------------------------------------------
const stateFileErrorSrc = section('function stateFileError(detail) {', '\n\nconst DECIMAL_RE', 'stateFileError');

assert.doesNotMatch(
  stateFileErrorSrc,
  /remove it to start from empty state/i,
  'stateFileError must not suggest deleting the file as the recovery step',
);
assert.match(
  stateFileErrorSrc,
  /Do NOT delete it/i,
  'stateFileError must explicitly warn against deleting the file',
);
assert.match(
  stateFileErrorSrc,
  /StaleRevocationRoot/,
  'stateFileError must explain the StaleRevocationRoot consequence of an empty-tree restart',
);
assert.match(
  stateFileErrorSrc,
  /fail-open/i,
  'stateFileError must explain that republishing an empty tree un-revokes everything (fail-open)',
);

// ---------------------------------------------------------------------------
// 3. saveIdPState()는 성공 여부를 boolean으로 돌려준다. /idp/revoke는 저장 실패 시
//    이 요청이 만든 변경만 롤백하고 5xx를 반환한다. 발급 경로(둘 다)는 실패해도 발급은
//    계속하되 응답에 persistenceWarning을 구조적으로 싣는다.
// ---------------------------------------------------------------------------
const saveIdPStateSrc = section('function saveIdPState() {', '\n\n// 기동 시 1회', 'saveIdPState');
assert.match(saveIdPStateSrc, /return true;/, 'saveIdPState must report success');
assert.match(saveIdPStateSrc, /return false;/, 'saveIdPState must report failure');

const revokeHandlerSrc = section(
  "app.post('/idp/revoke', requireIdPAdmin, serializeAdminMutation(async (req, res) => {",
  "\n// 관리자 전용 게시 엔드포인트",
  '/idp/revoke handler',
);
assert.match(
  revokeHandlerSrc,
  /const saved = saveIdPState\(\);\s*\n\s*if \(!saved\) \{/,
  '/idp/revoke must check saveIdPState()\'s return value',
);
assert.match(
  revokeHandlerSrc,
  /pendingAdds\.delete\(leafKey\)/,
  '/idp/revoke must roll back the pendingAdds mutation it made when the save fails',
);
assert.match(
  revokeHandlerSrc,
  /res\.status\(500\)\.json\(\{[\s\S]*?error:[\s\S]*?please retry/,
  '/idp/revoke must return a 5xx with a retry-oriented message when persistence fails',
);
// 실패해도 200으로 보고돼서는 안 된다는 것을 직접 확인한다: 롤백 분기 안에는
// `pending: true` 같은 성공 응답이 없어야 한다.
const revokeFailureBranch = revokeHandlerSrc.slice(revokeHandlerSrc.indexOf('if (!saved)'));
const revokeFailureBranchEnd = revokeFailureBranch.indexOf('\n    }\n');
assert.doesNotMatch(
  revokeFailureBranch.slice(0, revokeFailureBranchEnd === -1 ? undefined : revokeFailureBranchEnd),
  /pending:\s*true/,
  '/idp/revoke\'s save-failure branch must not also report pending: true',
);

// /idp/publish/commit도 상태를 크게 바꾼다(트리 전진·대기열 정리·로그 축출). 저장이
// 실패했는데 200을 돌려주면, 운영자는 게시가 확정된 줄 알지만 재시작 후 IdP는 커밋 이전
// root를 서빙한다 — 체인에는 새 root가 있으므로 폐기된 사용자가 아니라 **전원**의
// execute()가 StaleRevocationRoot로 막히고, 방금 게시한 폐기는 조용히 풀린다.
//
// 여기서 요구하는 것은 5xx가 아니라 구조적 경고 필드다: v2 전진은 append-only라 되돌릴
// 수 없고 preparedPublish도 이미 비워져 커밋을 재시도할 수 없다(재시도하면 409다).
// 그래서 발급 경로와 같은 선례를 따른다 — 작업은 성공으로 보고하되 저장 실패를 응답에
// 실어 운영자가 알게 한다.
const commitPersistSrc = section(
  "app.post('/idp/publish/commit', requireIdPAdmin, serializeAdminMutation(async (req, res) => {",
  '\n// --- 계정 층(사람 차단) 관리자 엔드포인트 ---',
  '/idp/publish/commit persistence',
);
assert.match(
  commitPersistSrc,
  /const persist(ed|enceWarning|Warning)\s*=\s*saveIdPState\(\)/,
  '/idp/publish/commit must capture saveIdPState()\'s return value, not call it bare',
);
assert.match(
  commitPersistSrc,
  /persistenceWarning/,
  '/idp/publish/commit must surface a structural persistenceWarning field when the save fails',
);

for (const marker of [
  // /token (PAR/authorization-code flow)
  "issuanceLog.set(String(record.token_nonce), { uid: record.uid, maxHeight: record.max_height });",
  // verifyPiIAndIssueToken (legacy /sso_with_credentials + /consent_result flow)
  "issuanceLog.set(rToken.toString(), { uid: user.uid, maxHeight: maxHeight.toString() });",
]) {
  const idx = src.indexOf(marker);
  assert(idx !== -1, `expected issuance call site not found: ${marker}`);
  const nearby = src.slice(idx, idx + 900);
  assert.match(
    nearby,
    /const persist(ed|enceWarning|Warning)/,
    `issuance path near "${marker.slice(0, 40)}..." must capture saveIdPState()'s result`,
  );
  assert.match(
    nearby,
    /persistenceWarning/,
    `issuance path near "${marker.slice(0, 40)}..." must surface a structural persistenceWarning field, not just a log line, when the save fails`,
  );
}

// ---------------------------------------------------------------------------
// 4-1. usedNonces는 기동 시 issuanceLog의 키로 seed된다(재전송 방지가 재시작을 넘어
//      살아남게 하기 위함), issuanceLog 복원 이후에 이뤄져야 한다.
// ---------------------------------------------------------------------------
const loadIdPStateSrc = section('async function loadIdPState() {', '\n\nawait loadIdPState();', 'loadIdPState');

assert.match(
  loadIdPStateSrc,
  /usedNonces\.clear\(\);\s*\n\s*for \(const rToken of issuanceLog\.keys\(\)\) usedNonces\.add\(rToken\);/,
  'loadIdPState must seed usedNonces from issuanceLog keys',
);
const issuanceRestoreIdx = loadIdPStateSrc.indexOf('issuanceLog.clear();');
const usedNoncesSeedIdx = loadIdPStateSrc.indexOf('usedNonces.clear();');
assert(issuanceRestoreIdx !== -1 && usedNoncesSeedIdx !== -1, 'both issuanceLog restore and usedNonces seed must be present');
assert(
  usedNoncesSeedIdx > issuanceRestoreIdx,
  'usedNonces must be seeded after issuanceLog is restored from disk, not before',
);

// ---------------------------------------------------------------------------
// 4-2. 축출은 만료(maxHeight + CREDENTIAL_LIFETIME_BLOCKS) 기준이어야 하고, usedNonces는
//      축출 로직이 절대 건드리면 안 된다(건드리면 오래된 r_token의 재전송이 다시 열린다).
// ---------------------------------------------------------------------------
const commitHandlerSrc = section(
  "app.post('/idp/publish/commit', requireIdPAdmin, serializeAdminMutation(async (req, res) => {",
  "\n// --- 계정 층(사람 차단) 관리자 엔드포인트 ---",
  '/idp/publish/commit handler',
);
assert.match(
  commitHandlerSrc,
  /BigInt\(entry\.maxHeight\) \+ CREDENTIAL_LIFETIME_BLOCKS < evictionCutoff/,
  'eviction must be keyed off maxHeight + CREDENTIAL_LIFETIME_BLOCKS, not a count or age cutoff',
);
assert.doesNotMatch(
  commitHandlerSrc,
  /\.slice\(0,\s*\d+\)|issuanceLog\.size\s*>\s*\d+|Date\.now\(\)\s*-.*>\s*\d+/,
  'eviction must not use a count-based (LRU) or wall-clock-age (TTL) cutoff',
);
// 끝 마커는 **마지막** preparedPublish = null 이어야 한다. root 불일치 분기(영구 500을
// 막으려고 무효가 된 prepare를 버리는 곳)에도 같은 문장이 있어서, 첫 등장을 쓰면 축출
// 블록보다 앞이라 구간이 뒤집힌다.
const evictionBlock = commitHandlerSrc.slice(
  commitHandlerSrc.indexOf('issuanceLog/auidILog 축출'),
  commitHandlerSrc.lastIndexOf('preparedPublish = null;'),
);
// (코드 주석에서 usedNonces를 "여기서 건드리지 않는다"고 설명하느라 텍스트에 언급은
// 되므로, 언급 자체가 아니라 실제 변경 호출(add/delete/clear)이 없는지를 검사한다.)
assert.doesNotMatch(
  evictionBlock,
  /usedNonces\.(add|delete|clear)\(/,
  'the eviction block must never mutate usedNonces — replay protection must not shrink',
);
assert.match(evictionBlock, /issuanceLog\.delete\(rToken\)/, 'eviction must remove stale issuanceLog entries');
assert.match(evictionBlock, /auidILog\.delete\(auidI\)/, 'eviction must remove stale auidILog entries');

// 스키마 버전: v6(설계 문서 13.1절)에서 v2 트리와 그 필드를 제거하고 v3를 게시 상태의
// 유일한 진실로 승격했다. v5 파일은 이미 v3 스냅샷을 담고 있어 무손실로 올라오지만,
// **v4 이하는 마이그레이션 경로가 없다** — 리프 해시에서 층(session/account)을 되돌릴 수
// 없어 게시 집합을 복원할 방법이 없다. 조용히 빈 트리로 시작하면 폐기된 사용자가 아니라
// 전원이 StaleRevocationRoot로 막히므로, 명시적으로 거부해야 한다.
assert.match(src, /const IDP_STATE_FILE_VERSION = 6;/, 'state file schema version must be bumped for the v2 removal (13.1)');
assert.match(
  loadIdPStateSrc,
  /if \(fileVersion < 5\) \{[\s\S]*?throw stateFileError\(/,
  'loadIdPState must refuse version 4 or older files instead of silently starting with an empty v3 forest',
);
assert.match(
  loadIdPStateSrc,
  /must contain a v3 snapshot/,
  'loadIdPState must refuse a v5+ file that has no v3 snapshot — there would be no source of truth',
);

// ---------------------------------------------------------------------------
// 7. v2 -> v3: users에 disabled 플래그가 추가됐다. v1/v2 파일에는 disabled가 없으므로
//    "명시적 거부"가 아니라 "누락 = false로 마이그레이션"이어야 한다(계정 층 차단
//    기능이 생기기 전에는 어떤 계정도 disabled일 수 없었으므로 손실이 없다는 것이
//    이 저장소가 택한 근거 — docs/REVOCATION_FOLLOWUPS.md, custom_idp.js 주석 참고).
// ---------------------------------------------------------------------------
assert.match(
  loadIdPStateSrc,
  /hasDisabledField/,
  'loadIdPState must explicitly branch on whether the disabled field is present (v3) or absent (v1/v2)',
);
// 버전 게이트는 알려진 버전 전체를 통과시키고, 마이그레이션 불가는 **그 다음** 검사에서
// 이유와 함께 거부한다. 게이트에서 바로 잘라내면 "모르는 버전"과 "알지만 되살릴 수 없는
// 버전"이 같은 메시지를 받아 운영자가 원인을 알 수 없다.
assert.match(
  loadIdPStateSrc,
  /\[1,\s*2,\s*3,\s*4,\s*5,\s*6\]\.includes\(fileVersion\)/,
  'the version gate must list every known version, including 6',
);

// serializeIdPState must persist disabled per account, mirroring how lastAuid is persisted.
const serializeSrc = section('function serializeIdPState() {', '\n}\n\n// 상태가 바뀔 때마다', 'serializeIdPState');
assert.match(
  serializeSrc,
  /disabled: Object\.fromEntries\(Object\.entries\(users\)\.map\(\(\[name, u\]\) => \[name, Boolean\(u\.disabled\)\]\)\)/,
  'serializeIdPState must persist each account\'s disabled flag',
);

// ---------------------------------------------------------------------------
// 8. 계정 층 관리자 엔드포인트는 requireIdPAdmin을 쓴다(requireIdPAuditor가 아니다) —
//    조회가 아니라 폐기와 같은 등급의 관리 조작이기 때문이다.
// ---------------------------------------------------------------------------
assert.match(
  src,
  /app\.post\('\/idp\/account\/set_disabled',\s*requireIdPAdmin,/,
  '/idp/account/set_disabled must require admin auth',
);
assert.match(
  src,
  /app\.post\('\/idp\/account\/unpin_auid',\s*requireIdPAdmin,/,
  '/idp/account/unpin_auid must require admin auth',
);

// disabled 계정에는 재바인딩 복구(unpin)를 거부해야 한다 — 안 그러면 부정 사용으로
// 차단한 계정이 복구 흐름으로 되살아난다.
const unpinHandlerSrc = section(
  "app.post('/idp/account/unpin_auid', requireIdPAdmin, async (req, res) => {",
  "\n// === v3(이중 트리) 조회",
  '/idp/account/unpin_auid handler',
);
assert.match(
  unpinHandlerSrc,
  /if \(user\.disabled\) \{\s*\n\s*return res\.status\(409\)/,
  '/idp/account/unpin_auid must refuse to unpin a disabled account',
);

// ---------------------------------------------------------------------------
// 5. 조회(B2 역추적) 엔드포인트에 requireIdPAuditor가 걸려 있다.
//
// 관리자(requireIdPAdmin)가 아니라 감사자여야 한다 — 두 권한은 의도적으로 분리돼 있다.
// 조회는 auid_i/r_token으로 uid를 특정하는 역추적이고, 폐기(/idp/revoke)와 게시
// (/idp/publish/*)는 관리자 조작이다. RP(server.js)가 데모를 위해 감사자 시크릿을 들지만,
// 그렇다고 폐기 권한까지 갖게 해서는 안 된다.
// ---------------------------------------------------------------------------
assert.match(
  src,
  /app\.post\('\/idp\/lookup_uid_by_r_token',\s*requireIdPAuditor,/,
  '/idp/lookup_uid_by_r_token must require auditor auth (not admin)',
);
assert.match(
  src,
  /app\.post\('\/idp\/lookup_uid_by_auid_i',\s*requireIdPAuditor,/,
  '/idp/lookup_uid_by_auid_i must require auditor auth (not admin)',
);
// 폐기·게시는 반대로 관리자여야 한다 — 분리가 한쪽으로만 성립하면 의미가 없다.
assert.match(
  src,
  /app\.post\('\/idp\/revoke',\s*requireIdPAdmin,/,
  '/idp/revoke must stay on admin auth, not auditor',
);

// ---------------------------------------------------------------------------
// 6. loadIdPState의 폐기 트리 복원 실패가 원시 에러가 아니라 stateFileError로 감싸진다.
//    13.1에서 v2 재구성이 사라지고 v3 restore가 그 자리를 물려받았다 — 게시 상태의
//    유일한 진실이므로 여기서 실패하면 조용히 넘어가면 안 된다.
// ---------------------------------------------------------------------------
assert.match(
  loadIdPStateSrc,
  /\} catch \(err\) \{\s*\n\s*throw stateFileError\(`v3 restore failed/,
  'the v3 forest restore must wrap failures in stateFileError',
);
// v2 트리를 되살리는 코드가 다시 들어오지 않는지 고정한다. 남아 있으면 "게시의 진실이
// 둘"인 상태로 되돌아가고, 13.1이 실측으로 잡아낸 '먹이를 못 받는 거울' 결함이 재발한다.
// 주석은 v2를 **역사로** 계속 언급하므로(왜 그렇게 됐는지가 코드보다 중요하다), 주석을
// 걷어낸 뒤 실제 코드만 본다.
const codeOnly = src
  .split('\n')
  .filter((l) => !l.trim().startsWith('//'))
  .join('\n');
// 식별자가 **코드로 쓰이는** 모양만 잡는다. 마이그레이션 안내 문구처럼 사라진 필드
// 이름을 문자열로 언급하는 것은 정상이고(운영자가 무엇이 없어졌는지 알아야 한다),
// 그것까지 막으면 검사가 문서화를 방해한다.
for (const [name, re] of [
  ['revocationTreeV2', /\brevocationTreeV2\b/],
  ['mutationLogV2', /\bmutationLogV2\b/],
  ['v2Has()', /\bv2Has\s*\(/],
  ['epochV2 (대입/인자)', /\bepochV2\s*[=,)]/],
  ['seqV2 (대입/인자)', /\bseqV2\s*[=,)]/],
  ['v2Leaves (속성 접근/키)', /\bv2Leaves\s*[:.]|\.v2Leaves\b/],
]) {
  assert.doesNotMatch(codeOnly, re, `custom_idp.js must not carry the v2 tree any more — ${name} (13.1)`);
}
assert.match(
  src,
  /function publishedLeaves\(\) \{\s*\n\s*return \[\.\.\.revocationV3\.publishedLeafSet\(\)\];/,
  'publishedLeaves() must be sourced from the v3 forest',
);
// 중복제거의 기준도 v3여야 한다. 이것만 v2에 남으면 v3가 "이미 있다"고 답하지 못해
// 같은 리프가 매 회차 다시 삽입 시도된다(반대로 v2에만 두면 13.1이 잡은 결함이 된다).
assert.match(
  src,
  /if \(!\(await revocationV3\.hasLeaf\(leafKey\)\)\) addedValues\.push\(leafKey\);/,
  "publish/prepare must dedupe against the v3 forest",
);

console.log('PASS: custom_idp.js state-persistence fixes (items 1-6) are present in source.');
