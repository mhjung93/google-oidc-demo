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
  "app.post('/idp/revoke', requireIdPAdmin, async (req, res) => {",
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
  "app.post('/idp/publish/commit', requireIdPAdmin, async (req, res) => {",
  "\n// 지갑이 자기 witness를",
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
const evictionBlock = commitHandlerSrc.slice(
  commitHandlerSrc.indexOf('issuanceLog/auidILog 축출'),
  commitHandlerSrc.indexOf('preparedPublish = null;'),
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

// 스키마 버전: auidILog가 { uid, maxHeight } 모양으로 바뀌었으니 버전이 올라가야 하고,
// 옛 파일(v1)은 조용히 오독되지 않고 명시적으로 처리(이 저장소는 무손실 마이그레이션을
// 택함 — 근거는 코드 주석과 보고서 참고)돼야 한다.
assert.match(src, /const IDP_STATE_FILE_VERSION = 2;/, 'state file schema version must be bumped for the auidILog shape change');
assert.match(
  loadIdPStateSrc,
  /isLegacyAuidILog/,
  'loadIdPState must explicitly branch on the legacy (v1) auidILog shape rather than assuming the new shape',
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
// 6. loadIdPState의 트리 재구성 insert() 실패가 원시 에러가 아니라 stateFileError로 감싸진다.
// ---------------------------------------------------------------------------
assert.match(
  loadIdPStateSrc,
  /try \{\s*\n\s*for \(const leafKey of leaves\) await tree\.insert\(BigInt\(leafKey\)\);\s*\n\s*\} catch \(err\) \{\s*\n\s*throw stateFileError\(/,
  'the revokedLeaves rebuild must wrap insert() failures in stateFileError',
);

console.log('PASS: custom_idp.js state-persistence fixes (items 1-6) are present in source.');
