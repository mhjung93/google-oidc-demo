#!/usr/bin/env bash
# 테스트 실행 진입점.
#
# 이 저장소의 테스트는 개별 node 스크립트라, 지금까지 "무엇을 돌려야 하는지"를 사람이
# 기억해야 했다. 그래서 실제로 관련 있는 테스트가 조용히 누락되는 일이 생겼다.
# 여기서 의존성별로 묶어 한 번에 돌린다.
#
#   bash scripts/run_tests.sh            # unit + circuit (자체 완결, 기본값)
#   bash scripts/run_tests.sh unit       # 외부 의존 없음, 빠름
#   bash scripts/run_tests.sh circuit    # circom/snarkjs 필요. 느리다(회로 컴파일)
#   bash scripts/run_tests.sh chain      # hardhat 노드(:8545) 필요. IdP는 스스로 격리 기동
#   bash scripts/run_tests.sh live       # 데모 스택(:3000/:4000/:5001) + 관리자 시크릿 필요
#   bash scripts/run_tests.sh all
#
# live 그룹은 실행 중인 IdP의 폐기 트리를 실제로 바꾸고(되돌릴 수 없음) 체인 블록을
# 진행시킨다. CI에서 돌릴 수 있는 것은 unit·circuit·chain이다.
set -uo pipefail
cd "$(dirname "$0")/.."

UNIT=(
  tests/test_ps.js
  tests/test_rid_not_leaked.js
  tests/test_uid_wallet_boundary.js
  tests/test_idp_state_persistence.js
  tests/test_idp_publish_invariants.js
  tests/test_wallet_revocation_cache.js
  tests/test_wallet_revocation_sync_recovery.mjs
)

CIRCUIT=(
  tests/test_eddsa.js
  tests/test_auid_salt_binding.js
  tests/test_pi_arid_i_no_rid.js
  tests/test_pi_ppid_poseidon.js
  tests/test_ppid_cross_rp_unlinkability.js
  tests/test_imt_v2_lib.js
  tests/test_imt_v2_nonmembership_circuit.mjs
  tests/test_pi_pk_i_v2_witness.mjs
  tests/test_pi_pk_i_revocation.mjs
)

# hardhat 노드만 있으면 되는 것들. IdP가 필요하면 테스트가 스스로 격리 인스턴스를 띄운다
# (tests/helpers/isolated_idp.mjs).
CHAIN=(
  tests/test_idp_publish_behavior.mjs
)

# 살아있는 데모 스택과 IDP_ADMIN_SECRET이 필요하다.
LIVE=(
  tests/test_idp_revoke_endpoint.js
  tests/test_revocation_e2e.js
  tests/test_imt_v2_wiring.js
  tests/test_idp_account_admin.js
  tests/test_par_endpoint.js
  tests/test_authorize_endpoint.js
  tests/test_token_endpoint.js
  tests/test_token_legacy_idptoken.js
  tests/test_verify_statement_endpoint.js
  tests/test_par_authorize_token_e2e.js
  tests/test_wallet_login_job.js
  tests/test_wallet_login_loopback.js
  tests/test_mode2_e2e_onchain.js
)

# 은퇴한 v1 폐기 트리를 테스트한다. Stage B에서 프로덕션 경로가 v2로 넘어갔고
# test_imt_nonmembership_circuit.mjs는 /tmp 하드코딩 탓에 clean checkout에서 돌지 않는다.
# 참고용으로 남겨 두되 어느 그룹에도 넣지 않는다:
#   tests/test_imt_lib.js, tests/test_imt_nonmembership_circuit.mjs

GROUP="${1:-default}"
case "$GROUP" in
  unit)    FILES=("${UNIT[@]}") ;;
  circuit) FILES=("${CIRCUIT[@]}") ;;
  chain)   FILES=("${CHAIN[@]}") ;;
  live)    FILES=("${LIVE[@]}") ;;
  all)     FILES=("${UNIT[@]}" "${CIRCUIT[@]}" "${CHAIN[@]}" "${LIVE[@]}") ;;
  default) FILES=("${UNIT[@]}" "${CIRCUIT[@]}") ;;
  *) echo "알 수 없는 그룹: $GROUP (unit|circuit|chain|live|all)" >&2; exit 2 ;;
esac

echo "== 그룹 '$GROUP' — ${#FILES[@]}개 실행 =="
PASSED=(); FAILED=()
for f in "${FILES[@]}"; do
  printf '  %-52s ' "$f"
  if out=$(node "$f" 2>&1); then
    echo "PASS"
    PASSED+=("$f")
  else
    echo "FAIL"
    FAILED+=("$f")
    echo "$out" | tail -15 | sed 's/^/      /'
  fi
done

echo
echo "== 통과 ${#PASSED[@]} / 실패 ${#FAILED[@]} =="
if [ ${#FAILED[@]} -gt 0 ]; then
  printf '실패: %s\n' "${FAILED[@]}"
  exit 1
fi
