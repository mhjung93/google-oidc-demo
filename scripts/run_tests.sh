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
#   bash scripts/run_tests.sh contract   # 컨트랙트(test/*.test.mjs). hardhat 인프로세스 체인
#   bash scripts/run_tests.sh live       # 데모 스택(:3000/:4000/:5001) + 관리자 시크릿 필요
#   bash scripts/run_tests.sh all
#
# live 그룹은 실행 중인 IdP의 폐기 트리를 실제로 바꾸고(되돌릴 수 없음) 체인 블록을
# 진행시킨다. CI에서 돌릴 수 있는 것은 unit·circuit·chain·contract이다.
set -uo pipefail
cd "$(dirname "$0")/.."

UNIT=(
  tests/test_ps.js
  tests/test_uid_wallet_boundary.js
  tests/test_idp_state_persistence.js
  tests/test_idp_publish_invariants.js
  tests/test_wallet_revocation_cache.js
  tests/test_imt_v3_lib.js
  tests/test_mode3_revocation_tree.js
  tests/test_mode3_issuance.js
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
  tests/test_pi_pk_i_v3_shard.mjs
  tests/test_insert_transition_circuit.mjs
  tests/test_mode3_commit_scheme.mjs
  tests/test_pi_cred_witness.mjs
)

# hardhat 노드만 있으면 되는 것들. IdP가 필요하면 테스트가 스스로 격리 인스턴스를 띄운다
# (tests/helpers/isolated_idp.mjs).
CHAIN=(
  tests/test_idp_publish_behavior.mjs
  tests/test_idp_revocation_v3.mjs
  tests/test_wallet_revocation_v3.mjs
  tests/test_publish_v4_cycle.mjs
  tests/test_cia_register_issue.mjs
)

# 살아있는 데모 스택과 IDP_ADMIN_SECRET이 필요하다.
LIVE=(
  # RP 백엔드(:3000)의 노출면 — 민감 파일 비공개, 추적 권한 분리, 열린 릴레이 부재.
  tests/test_rp_server_exposure.js
  # IdP가 크레덴셜 유효기간 상한을 강제하는가(폐기 무력화 방지).
  tests/test_max_height_bound.js
  # localhost:4000/register_rp를 부른다(127.0.0.1이 아니라 localhost라 분류에서 놓쳤었다).
  tests/test_rid_not_leaked.js
  tests/test_idp_revoke_endpoint.js
  tests/test_revocation_e2e.js
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
  contract)
    # 컨트랙트 테스트는 hardhat이 자기 인프로세스 체인에서 돌린다(:8545가 필요 없다).
    # 파일 단위로 node를 부르는 아래 루프와 실행 방식이 달라 여기서 끝낸다.
    #
    # 그전까지 test/*.test.mjs는 어느 그룹에도 없어서 `npx hardhat test`를 사람이
    # 기억해야 했다 — 이 파일이 없애려던 바로 그 상황이다(2026-09-07).
    echo "== 그룹 'contract' — npx hardhat test =="
    npx hardhat test
    exit $?
    ;;
  live)
    # live 그룹은 실행 중인 IdP의 폐기 트리를 **되돌릴 수 없게** 바꾸고(append-only)
    # 체인 블록을 수백 개 진행시킨다. 격리 하네스(tests/helpers/isolated_idp.mjs)가
    # 있는데도 이 16개는 아직 개발 인스턴스를 직접 쓴다 — 실수로 돌리는 일이 없도록
    # 명시적 동의를 요구한다(2026-09-04 리뷰).
    if [ "${RUN_LIVE_TESTS:-}" != "yes" ]; then
      echo "live 그룹은 실행 중인 IdP의 폐기 트리를 되돌릴 수 없게 바꾸고 체인 블록을 진행시킵니다."
      echo "  - 폐기 리프가 쌓이고(append-only), 재기준화로 epoch가 오를 수 있습니다."
      echo "  - E2E는 매 실행마다 새 세션을 폐기합니다."
      echo "진행하려면 RUN_LIVE_TESTS=yes 를 설정하십시오."
      exit 2
    fi
    FILES=("${LIVE[@]}")
    ;;
  all)
    if [ "${RUN_LIVE_TESTS:-}" != "yes" ]; then
      echo "all 그룹은 live를 포함합니다. RUN_LIVE_TESTS=yes 를 설정하십시오(위 live 설명 참고)."
      exit 2
    fi
    # contract는 실행 방식이 달라 여기서 먼저 돌리고, 실패하면 거기서 멈춘다.
    npx hardhat test || exit 1
    FILES=("${UNIT[@]}" "${CIRCUIT[@]}" "${CHAIN[@]}" "${LIVE[@]}")
    ;;
  default) FILES=("${UNIT[@]}" "${CIRCUIT[@]}") ;;
  *) echo "알 수 없는 그룹: $GROUP (unit|circuit|chain|contract|live|all)" >&2; exit 2 ;;
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
