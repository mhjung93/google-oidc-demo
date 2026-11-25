#!/usr/bin/env bash
# 폐기(RCL) 체인(:8548, chainId 31340)용 두 번째 Blockscout — http://127.0.0.1:4001 (2026-11-25). 응용 체인용(:4000, zkid-blockscout)과 동시에 뜬다.
#   bash scripts/blockscout_rcl.sh up      # 띄우기(이미 떠 있으면 그대로)
#   bash scripts/blockscout_rcl.sh reset   # 색인을 비우고 다시 띄우기(체인을 새로 만들었을 때 — demo_split_start.sh 가 부른다)
#   bash scripts/blockscout_rcl.sh down    # 내리고 색인 볼륨까지 지우기
#   bash scripts/blockscout_rcl.sh status
# 설정은 .local/blockscout/compose.yml 을 그대로 쓰고 scripts/blockscout_rcl.compose.yml 로 체인·주소·포트만 바꾼다. 프로젝트 이름이 달라 볼륨·네트워크·컨테이너가 따로다.
set -u
cd "$(dirname "$0")/.." || exit 1
BASE=".local/blockscout/compose.yml"; OVER="scripts/blockscout_rcl.compose.yml"
MAIN="${BLOCKSCOUT_PROJECT:-zkid-blockscout}"; RCL="${BLOCKSCOUT_RCL_PROJECT:-zkid-blockscout-rcl}"
SERVICES="db redis verifier trace-adapter backend frontend proxy-rcl"   # 바탕의 proxy(:4000)는 띄우지 않는다
[ -f "$BASE" ] || { echo "Blockscout(RCL): $BASE 가 없어 건너뛴다"; exit 0; }
command -v docker >/dev/null 2>&1 || { echo "Blockscout(RCL): docker 가 없어 건너뛴다"; exit 0; }
[ "$RCL" != "$MAIN" ] || { echo "BLOCKED: RCL 스택의 프로젝트 이름이 응용 체인 스택과 같다($MAIN)" >&2; exit 2; }
dc() { docker compose -p "$RCL" -f "$BASE" -f "$OVER" "$@"; }
# 지우기 전에: 풀어 쓴 설정의 볼륨·네트워크 이름이 모두 이 프로젝트의 것이어야 한다 — 바탕 파일에 고정 이름·external 이 생기면 `down -v` 가 응용 체인 색인을 지운다(설정은 출력하지 않는다).
safe() {
  local cfg names bad; cfg=$(dc config 2>/dev/null) || { echo "BLOCKED: compose 설정을 풀지 못했다" >&2; return 1; }
  names=$(printf '%s\n' "$cfg" | grep -E '^ +name: ' | sed -E 's/^ +name: //' | tr -d '"'); bad=$(printf '%s\n' "$names" | grep -vE "^${RCL}_" | grep -c .)
  [ -n "$names" ] && [ "$bad" = 0 ] && ! printf '%s\n' "$cfg" | grep -qE 'external: true|container_name:' || { echo "BLOCKED: RCL 스택이 다른 스택과 볼륨·네트워크·컨테이너 이름을 나눠 쓴다 — 지우지 않는다" >&2; return 1; }
}
case "${1:-}" in
  up) safe && dc up -d $SERVICES ;;
  reset) safe && dc down -v && dc up -d $SERVICES ;;
  down) safe && dc down -v ;;
  status) dc ps ;;
  *) sed -n '2,7p' "$0"; exit 2 ;;
esac
