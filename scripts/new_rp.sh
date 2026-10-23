#!/usr/bin/env bash
# 새 RP 서버 한 줄 기동/정지(2026-10-22 설계 B §6, docs/superpowers/specs/2026-10-22-mode3-idp-pages-design.md "RP 서버·기동 명령" 절).
# IdP RP 페이지("새 RP 만들기")가 운영자에게 보여 주는 명령이다. 로컬(한 머신 데모, demo_web_reset.sh/demo_snap_reset.sh 가
# 띄운 것) 또는 --host 로 분리 데모의 RP VM(~/zkd-demo, demo_split_start.sh 가 쓰는 role.env 위에 덮어 기동)에 ssh 로 띄운다.
#
# 사용:
#   bash scripts/new_rp.sh NAME PORT KEY [--host IP] [--relayer N] [--countries 410,392] [--min-age 19] [--require-disclosure]
#   bash scripts/new_rp.sh NAME PORT [KEY] [--host IP] --stop
#   bash scripts/new_rp.sh --help
#
#   NAME   RP 이름, zk 로 시작하는 영숫자(최대 16자) — 예: zkTHREE
#   PORT   RP 가 들을 포트(로컬) 또는 --host 쪽 RP VM 의 공개 포트
#   KEY    IdP RP 페이지 "새 RP 만들기" 가 준 1회용 RP 키(64자 16진수). MODE3_RP_KEY 로만 전달한다 — 이 스크립트가
#          만드는 어떤 파일에도 쓰지 않고, 로그·표준출력에도 찍지 않는다. --stop 일 때는 생략할 수 있다.
#
# 옵션:
#   --host IP              로컬이 아니라 이 IP 의 RP VM(SPLIT_SSH_USER, 기본 zkd)에 ssh 로 띄운다(분리 데모)
#   --relayer N             릴레이어 계정 인덱스(기본: 로컬은 3+기존 RP 수, --host 는 3). 겹치면 nonce 충돌로 배포 실패
#   --countries C1,C2,...   MODE3_ALLOWED_COUNTRIES(숫자 국가코드 CSV, 예: 410,392)
#   --min-age N             MODE3_MIN_AGE
#   --require-disclosure    MODE3_REQUIRE_DISCLOSURE=1(국가·나이 술어 공개 요구)
#   --stop                  이 NAME/PORT 의 RP 서버만 내린다(다른 포트·프로세스는 건드리지 않음). KEY 는 생략하거나
#                           (주더라도) 쓰지 않는다
#
# 기동 전에는 그 PORT 가 이미 쓰이고 있는지 먼저 본다(로컬은 ss, --host 는 ssh 로 그 VM 의 ss) — 선점이면 바로 실패한다.
#
# 전제(로컬): demo_web_reset.sh 또는 demo_snap_reset.sh 로 데모가 떠 있어야 한다($DEMO_LOG_DIR/demo_env.txt 필요, 기본 /tmp/mode3-demo).
# 전제(--host): 그 VM 의 ~/zkd-demo 에 role.env(rp1 의 것)와 코드·node_modules·Node 실행 파일이 있어야 한다(demo_split_start.sh SYNC=1 참고).
#
# 종료 코드: 0 성공(기동/정지/--help) · 1 사용법·인자 검증 오류, 또는 기동/정지 실패
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
사용: bash scripts/new_rp.sh NAME PORT KEY [--host IP] [--relayer N] [--countries 410,392] [--min-age 19] [--require-disclosure]
      bash scripts/new_rp.sh NAME PORT [KEY] [--host IP] --stop
      bash scripts/new_rp.sh --help

  NAME   RP 이름, zk 로 시작하는 영숫자(최대 16자) — 예: zkTHREE
  PORT   RP 가 들을 포트(로컬) 또는 --host 쪽 RP VM 의 공개 포트
  KEY    IdP RP 페이지 "새 RP 만들기" 가 준 1회용 RP 키, 64자 16진수(MODE3_RP_KEY 로만 전달 — 파일에 쓰지 않고
         출력하지 않는다). --stop 일 때는 생략할 수 있다

옵션:
  --host IP              이 IP 의 RP VM(SPLIT_SSH_USER, 기본 zkd)에 ssh 로 띄운다(분리 데모). 없으면 로컬(한 머신 데모)
  --relayer N            릴레이어 계정 인덱스(기본: 로컬은 3+기존 RP 수, --host 는 3)
  --countries C1,C2,...  MODE3_ALLOWED_COUNTRIES(숫자 국가코드 CSV)
  --min-age N            MODE3_MIN_AGE
  --require-disclosure   MODE3_REQUIRE_DISCLOSURE=1
  --stop                 이 NAME/PORT 의 RP 서버만 내린다. KEY 는 생략하거나(주더라도) 쓰지 않는다

기동 전에 그 PORT 가 이미 쓰이고 있으면(로컬은 ss, --host 는 ssh 로 그 VM 의 ss) 바로 실패한다.

전제(로컬): demo_web_reset.sh / demo_snap_reset.sh 로 데모가 떠 있어야 한다($DEMO_LOG_DIR/demo_env.txt, 기본 /tmp/mode3-demo).
전제(--host): 그 VM 의 ~/zkd-demo 에 role.env 와 코드·Node 실행 파일이 있어야 한다.

종료 코드: 0 성공 · 1 사용법·인자 검증 오류 또는 기동/정지 실패
EOF
}

if [ $# -eq 0 ] || [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then usage; exit 0; fi

NAME="${1:?NAME}"; PORT="${2:?PORT}"; shift 2
KEY=""
if [ $# -gt 0 ] && [[ "$1" != --* ]]; then KEY="$1"; shift; fi
HOST=""; RELAYER=""; COUNTRIES=""; MIN_AGE=""; REQ=""; STOP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="${2:?--host 는 IP 가 필요하다}"; shift 2;;
    --relayer) RELAYER="${2:?--relayer 는 숫자가 필요하다}"; shift 2;;
    --countries) COUNTRIES="${2:?--countries 는 CSV 가 필요하다}"; shift 2;;
    --min-age) MIN_AGE="${2:?--min-age 는 숫자가 필요하다}"; shift 2;;
    --require-disclosure) REQ=1; shift;;
    --stop) STOP=1; shift;;
    --help|-h) usage; exit 0;;
    *) echo "모르는 옵션: $1" >&2; exit 1;;
  esac
done

[[ "$NAME" =~ ^zk[A-Za-z0-9]{1,15}$ ]] || { echo "NAME 은 zk 로 시작하는 영숫자(최대 16자)여야 한다: $NAME" >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || { echo "PORT 는 1-65535 사이 숫자여야 한다: $PORT" >&2; exit 1; }
if [ -n "$RELAYER" ]; then [[ "$RELAYER" =~ ^[0-9]+$ ]] || { echo "--relayer 는 숫자여야 한다: $RELAYER" >&2; exit 1; }; fi
if [ -n "$MIN_AGE" ]; then [[ "$MIN_AGE" =~ ^[0-9]+$ ]] || { echo "--min-age 는 숫자여야 한다: $MIN_AGE" >&2; exit 1; }; fi
if [ -n "$COUNTRIES" ]; then [[ "$COUNTRIES" =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo "--countries 는 숫자 CSV 여야 한다(예: 410,392): $COUNTRIES" >&2; exit 1; }; fi
if [ "$STOP" != 1 ]; then [ -n "$KEY" ] || { echo "KEY 가 필요하다(--stop 이 아니면): bash scripts/new_rp.sh NAME PORT KEY ..." >&2; exit 1; }; fi
if [ -n "$KEY" ]; then [[ "$KEY" =~ ^[0-9a-f]{64}$ ]] || { echo "KEY 형식이 올바르지 않다(64자 16진수 소문자여야 한다)" >&2; exit 1; }; fi

LOGS="${DEMO_LOG_DIR:-/tmp/mode3-demo}"

if [ -z "$HOST" ]; then
  # 로컬(한 머신 데모)
  if [ "$STOP" = 1 ]; then
    FOUND=0
    for pid in $(ss -ltnp 2>/dev/null | grep ":$PORT " | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
      if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q 'mode3_rp\.js'; then
        kill "$pid" && echo "stop $NAME :$PORT (pid $pid)"; FOUND=1
      fi
    done
    [ "$FOUND" = 1 ] || echo "$NAME :$PORT 에 떠 있는 mode3_rp.js 가 없다(이미 내려감)"
    exit 0
  fi
  ss -ltn | grep -q ":$PORT " && { echo "PORT $PORT 가 이미 쓰이고 있다 — 다른 포트를 쓰거나 먼저 --stop 으로 내릴 것" >&2; exit 1; }
  N=$(pgrep -fc '^node mode3_rp\.js$' 2>/dev/null || true); RELAYER="${RELAYER:-$((3 + ${N:-0}))}"
  [ -s "$LOGS/demo_env.txt" ] || { echo "$LOGS/demo_env.txt 가 없다 — 먼저 demo_web_reset.sh / demo_snap_reset.sh 로 데모를 띄울 것" >&2; exit 1; }
  set -a; . "$LOGS/demo_env.txt"; set +a
  export CIA_ADMIN_OPEN="${CIA_ADMIN_OPEN:-1}" MODE3_VERIFIER_ADDRESS="" MODE3_RP_FACTORY_ADDRESS="" \
    MODE3_WALLET_AGENT_ORIGIN="http://localhost:5100" MODE3_CIA_URL="http://localhost:4100" CIA_RPC_URL="http://127.0.0.1:8545"
  export MODE3_RP_NAME="$NAME" MODE3_RP_PORT="$PORT" MODE3_RP_PUBLIC_ORIGIN="http://localhost:$PORT" \
    MODE3_RP_KEY="$KEY" MODE3_RELAYER_INDEX="$RELAYER" \
    MODE3_RP_REGISTRATION_FILE="mode3_rp_${NAME}_registration.json" MODE3_RP_LOGIN_LOG="mode3_rp_${NAME}_logins.jsonl"
  [ -n "$COUNTRIES" ] && export MODE3_ALLOWED_COUNTRIES="$COUNTRIES"
  [ -n "$MIN_AGE" ] && export MODE3_MIN_AGE="$MIN_AGE"
  [ -n "$REQ" ] && export MODE3_REQUIRE_DISCLOSURE=1
  setsid nohup node mode3_rp.js > "$LOGS/rp_${NAME}.log" 2>&1 < /dev/null &
  timeout 40 bash -c "until ss -ltn | grep -q ':$PORT '; do sleep 1; done" \
    && echo "$NAME up at http://localhost:$PORT (등록 요청 보냄 — IdP 관리자 승인 대기)" \
    || { echo "$NAME :$PORT 기동 실패 — $LOGS/rp_${NAME}.log" >&2; exit 1; }
else
  # --host: 분리 데모의 RP VM 에 ssh 로 띄운다
  U="${SPLIT_SSH_USER:-zkd}"
  if [ "$STOP" = 1 ]; then
    ssh -o BatchMode=yes "$U@$HOST" "pid=\$(ss -ltnp 2>/dev/null | grep ':$PORT ' | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | head -1); if [ -n \"\$pid\" ] && tr '\\0' ' ' < \"/proc/\$pid/cmdline\" 2>/dev/null | grep -q 'mode3_rp\\.js'; then kill \"\$pid\" && echo \"stop $NAME :$PORT (pid \$pid)\"; else echo \"$NAME :$PORT 에 떠 있는 mode3_rp.js 가 없다(이미 내려감)\"; fi"
    exit 0
  fi
  ssh -o BatchMode=yes "$U@$HOST" "ss -ltn | grep -q ':$PORT '" && { echo "$HOST:$PORT 가 이미 쓰이고 있다 — 다른 포트를 쓰거나 먼저 --stop 으로 내릴 것" >&2; exit 1; }
  RELAYER="${RELAYER:-3}"
  # MODE3_RP_KEY 는 role.env 파생 파일(rp_${NAME}.env)에 쓰지 않는다 — 기동 명령에 env 로 한 번만 얹는다(디스크에 남지 않게).
  KEY_Q=$(printf '%s' "$KEY" | sed "s/'/'\\\\''/g")
  ssh -o BatchMode=yes "$U@$HOST" "cd ~/zkd-demo && { grep -vE '^(MODE3_RP_PORT|MODE3_RP_NAME|MODE3_RP_PUBLIC_ORIGIN|MODE3_RELAYER_INDEX|MODE3_ALLOWED_COUNTRIES|MODE3_MIN_AGE|MODE3_REQUIRE_DISCLOSURE|MODE3_RP_REGISTRATION_FILE|MODE3_RP_LOGIN_LOG|MODE3_RP_KEY)=' role.env 2>/dev/null; echo MODE3_RP_PORT=$PORT; echo MODE3_RP_NAME=$NAME; echo MODE3_RP_PUBLIC_ORIGIN=http://$HOST:$PORT; echo MODE3_RELAYER_INDEX=$RELAYER; echo MODE3_RP_REGISTRATION_FILE=mode3_rp_${NAME}_registration.json; echo MODE3_RP_LOGIN_LOG=mode3_rp_${NAME}_logins.jsonl; ${COUNTRIES:+echo MODE3_ALLOWED_COUNTRIES=$COUNTRIES;} ${MIN_AGE:+echo MODE3_MIN_AGE=$MIN_AGE;} ${REQ:+echo MODE3_REQUIRE_DISCLOSURE=1;} } > rp_${NAME}.env && chmod 600 rp_${NAME}.env"
  ssh -o BatchMode=yes "$U@$HOST" "cd ~/zkd-demo && set -a && . ./rp_${NAME}.env && set +a && { MODE3_RP_KEY='$KEY_Q' setsid nohup \$HOME/zkd-demo/bin/node mode3_rp.js > logs/rp_${NAME}.log 2>&1 < /dev/null & }"
  for i in $(seq 1 40); do
    curl -s -m 2 -o /dev/null "http://$HOST:$PORT/mode3/health" && { echo "$NAME up at http://$HOST:$PORT (승인 대기)"; exit 0; }
    sleep 1
  done
  echo "$NAME :$PORT 기동 실패 — $HOST 의 ~/zkd-demo/logs/rp_${NAME}.log" >&2
  exit 1
fi
