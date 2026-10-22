#!/usr/bin/env bash
# Mode 3 VM 분리 데모 기동(2026-10-20). 체인 두 개(응용 :8547 chainId 31339, 폐기 :8548 chainId 31340)와 사용자 페이지(:5200)는 이 VM,
# IdP·zkONE·zkTWO 는 각자의 VM 에서 돈다. 이 VM 의 라이브 데모(:8545/:8546/:4100/:5100/:3100/:3101)는 건드리지 않는다.
# 전제: 이 VM 에서 세 VM 으로 키 ssh 가 되고, 각 VM 의 ~/zkd-demo 에 코드·node_modules·Node 실행 파일이 있다(없거나 코드를 고쳤으면 SYNC=1).
# 사용:  bash scripts/demo_split_start.sh                  # 새 체인으로 전부 다시 띄움(RP 승인은 IdP 관리자 페이지에서 수동)
#        AUTO_APPROVE=1 bash scripts/demo_split_start.sh   # RP 자동 승인
#        SYNC=1 bash scripts/demo_split_start.sh           # 먼저 코드·의존성·Node 를 세 VM 에 다시 보냄
#        bash scripts/demo_split_start.sh stop             # 분리 데모만 전부 내림
#        HEIGHT_GRID=100 bash scripts/demo_split_start.sh  # 만료(max_height) 올림 단위(기본 5 — 데모용. 코드 기본은 100, 2026-10-21)
#        WALLET_MODE=snap bash scripts/demo_split_start.sh  # Snap 모드(2026-10-22): 이 VM 의 지갑 자리에 에이전트(:5100, MODE3_WALLET_SECRETS=snap)+Snap 서버(:8082). 포트 5100 은 Snap 이 허용하는
#                                                          # 지갑 오리진(snap-mode3/src/index.js)이라 바꿀 수 없다 — 한 머신 데모(:5100)와 동시에 못 띄운다. scripts/demo_split_snap_reset.sh 가 이 값을 넣어 부른다(web 모드 리셋은 scripts/demo_split_reset.sh).
#        ADMIN_OPEN=0 bash scripts/demo_split_start.sh     # IdP 관리자 인증을 켠 채로(기본은 끔 — CIA_ADMIN_OPEN=1, 데모 전용, 2026-10-21)
# 주소는 SPLIT_HOST_IP·SPLIT_IDP_IP·SPLIT_RP1_IP·SPLIT_RP2_IP·SPLIT_SSH_USER 로 바꿀 수 있다. 로그는 DEMO_LOG_DIR(기본 /tmp/mode3-split).
# 새 체인은 Ethernal 플러그인을 싣지 않는 최소 hardhat 설정으로 띄운다 — 프로젝트 설정은 노드 기동 때 .env 의 Ethernal 워크스페이스를 초기화한다.
# 사용자 페이지는 이 VM 의 .env 를 읽지 않는다(DOTENV_CONFIG_PATH) — 라이브 IdP 의 고정 공개키 같은 값이 섞이지 않게.
# 다시 띄우면 체인이 새로 시작한다. 사용자 페이지는 데모 세대(MODE3_DEMO_GENERATION, 매 실행 새 값)를 보고 브라우저의 옛 등록·세션을 스스로 지운다(2026-10-21) —
# 이 스크립트 이전에 등록한 브라우저만 처음 한 번 "모두 지우기"가 필요하다. zkTWO 는 MODE3_REQUIRE_DISCLOSURE=1 로 로그인 때 국가·나이 술어를 요구한다.
set -u
cd "$(dirname "$0")/.."
U="${SPLIT_SSH_USER:-zkd}"; HOST="${SPLIT_HOST_IP:-192.168.226.128}"
IDP="${SPLIT_IDP_IP:-192.168.226.10}"; RP1="${SPLIT_RP1_IP:-192.168.226.11}"; RP2="${SPLIT_RP2_IP:-192.168.226.12}"
WALLET_MODE="${WALLET_MODE:-web}"
case "$WALLET_MODE" in web) USER_PORT=5200 ;; snap) USER_PORT=5100 ;; *) echo "WALLET_MODE 는 web 또는 snap: $WALLET_MODE"; exit 1 ;; esac
if [ "$WALLET_MODE" = "snap" ]; then [ -d snap-mode3/node_modules ] && [ -f snap-mode3/dist/bundle.js ] || { echo "BLOCKED: snap-mode3/node_modules 또는 dist/bundle.js 가 없다 — cd snap-mode3 && npm install && npm run build"; exit 1; }; fi
APP_PORT=8547 APP_CHAIN=31339 REV_PORT=8548 REV_CHAIN=31340 IDP_PORT=4100 RP1_PORT=3100 RP2_PORT=3101 SNAP_PORT=8082
LOGS="${DEMO_LOG_DIR:-/tmp/mode3-split}"; mkdir -p "$LOGS"
TS=$(date '+%Y%m%d-%H%M')
ADMIN="${CIA_ADMIN_SECRET:-admin123}"
WALLET_ORIGIN="http://localhost:$USER_PORT"
on() { local h="$1"; shift; ssh -o BatchMode=yes -o ConnectTimeout=5 "$U@$h" "$@"; }

# 이 VM 쪽은 포트 주인 중 명령줄이 우리 것과 맞는 것만 내린다(라이브 데모와 명령줄이 같은 사용자 페이지는 포트로 가른다).
stop_local() {
  for spec in "$APP_PORT:chain.config.cjs" "$REV_PORT:chain.config.cjs" "5200:mode3_user_static.js" "5100:mode3_wallet_agent.js" "$SNAP_PORT:mm-snap serve"; do
    port="${spec%%:*}"; want="${spec#*:}"
    for pid in $(ss -ltnp 2>/dev/null | grep ":$port " | grep -oE "pid=[0-9]+" | cut -d= -f2 | sort -u); do
      tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "$want" && kill "$pid" && echo "stop :$port (pid $pid)"
    done
  done
}
# VM 쪽 패턴의 [z] 는 pkill 이 자기를 부른 원격 셸을 잡지 않게 하는 것이다.
# 원격 기동은 `{ 명령 & }` 로 감싼다 — `a && b &` 로 쓰면 목록 전체가 백그라운드 서브셸이 되어 ssh 출력을 쥔 채 남고, ssh 가 끝나지 않는다.
stop_remote() {
  on "$IDP" "pkill -f '[z]kd-demo/bin/node cia.js' && echo 'stop IdP ($IDP)' || true"
  for h in "$RP1" "$RP2"; do on "$h" "pkill -f '[z]kd-demo/bin/node mode3_rp.js' && echo 'stop RP ($h)' || true"; done
}
if [ "${1:-}" = "stop" ]; then stop_remote; stop_local; exit 0; fi
echo "SPLIT_START $(date '+%H:%M:%S')  (logs: $LOGS)"

# 0. 내림
stop_remote; stop_local; sleep 2
for p in $APP_PORT $REV_PORT $USER_PORT; do ss -ltn | grep -q ":$p " && { echo "ABORT :$p 를 다른 프로세스가 쓰고 있다"; exit 1; }; done

# 1. (선택) 코드·의존성·Node 다시 보내기 — 서버가 읽는 것만. 비밀·상태 파일, .env, ptau, 문서는 보내지 않는다.
if [ "${SYNC:-0}" = "1" ]; then
  FILES="package.json package-lock.json cia.js mode3_rp.js lib mode3 artifacts build/mode3/pi_cred_vkey.json build/mode3/pi_idp_vkey.json build/mode3/pi_cred_final.zkey build/mode3/pi_idp_final.zkey build/mode3/pi_cred_js/pi_cred.wasm build/mode3/pi_idp_js/pi_idp.wasm node_modules"
  NODE_BIN="$(command -v node)"
  for h in "$IDP" "$RP1" "$RP2"; do
    on "$h" 'mkdir -p ~/zkd-demo/bin ~/zkd-demo/logs' && rsync -aR -e "ssh -o BatchMode=yes" $FILES "$U@$h:zkd-demo/" \
      && rsync -a -e "ssh -o BatchMode=yes" "$NODE_BIN" "$U@$h:zkd-demo/bin/node" && echo "sync $h ok" || { echo "sync $h failed"; exit 1; }
  done
fi

# 2. 옛 상태 파일은 새 체인과 맞지 않으므로 .bak-시각 으로 옮긴다(지우지 않는다). IdP 키(cia_keys.json)는 그대로 둔다.
on "$IDP" "cd ~/zkd-demo && for f in cia_state.json; do [ -e \$f ] && mv \$f \$f.bak-$TS && echo \"backup IdP \$f\"; done; true"
for h in "$RP1" "$RP2"; do
  on "$h" "cd ~/zkd-demo && for f in mode3_rp_registration.json mode3_rp_logins.jsonl; do [ -e \$f ] && mv \$f \$f.bak-$TS && echo \"backup $h \$f\"; done; true"
done

# 2b. Snap 모드: 이 VM 의 에이전트 상태 파일도 새 체인과 맞지 않는다 — .bak-시각 으로 옮긴다(MetaMask 안의 Snap 상태는 못 지운다 — 지갑 페이지 'Snap 초기화').
if [ "$WALLET_MODE" = "snap" ]; then for f in mode3_wallet_state.json mode3_wallet_rcl.json; do [ -e "$f" ] && mv "$f" "$f.bak-$TS" && echo "backup $f"; done; fi
# 3. 체인 두 개(Ethernal 없는 최소 설정, NAT 망에 연다)
cat > "$LOGS/chain.config.cjs" <<'EOF'
// 분리 데모 체인 전용 최소 설정(demo_split_start.sh 가 만든다) — Ethernal 플러그인·dotenv 를 싣지 않는다.
module.exports = { networks: { hardhat: { chainId: Number(process.env.HARDHAT_CHAIN_ID || 31337) } } };
EOF
start_chain() { # $1 포트 $2 chainId $3 이름
  HARDHAT_CHAIN_ID="$2" setsid nohup node node_modules/hardhat/internal/cli/bootstrap.js --config "$LOGS/chain.config.cjs" node --hostname 0.0.0.0 --port "$1" > "$LOGS/chain_$3.log" 2>&1 < /dev/null &
  timeout 60 bash -c "until ss -ltn | grep -q ':$1 '; do sleep 1; done" || { echo "chain $3 :$1 failed — $LOGS/chain_$3.log"; exit 1; }
  local got; got=$(curl -s -m 5 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "http://127.0.0.1:$1" | python3 -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null)
  [ "$got" = "$2" ] && echo "chain $3 :$1 up (chainId $got)" || { echo "chain $3 :$1 chainId 불일치(${got:-응답 없음})"; exit 1; }
}
start_chain $REV_PORT $REV_CHAIN rev
start_chain $APP_PORT $APP_CHAIN app

# 4. IdP 주소: 임시 상태 파일로 IdP 를 한 번 띄워 /cia/public_keys 의 ethAddress 를 읽는다(배포 스크립트 안내대로). 키는 idp VM 안에만 생긴다.
on "$IDP" "cd ~/zkd-demo && { CIA_STATE_FILE=/tmp/cia_keyprobe_state.json CIA_RPC_URL=http://$HOST:$REV_PORT setsid nohup \$HOME/zkd-demo/bin/node cia.js > logs/cia_keyprobe.log 2>&1 < /dev/null & }"
ADDR=$(on "$IDP" "for i in \$(seq 1 30); do r=\$(curl -s -m 2 http://127.0.0.1:$IDP_PORT/cia/public_keys) && [ -n \"\$r\" ] && { echo \"\$r\"; break; }; sleep 1; done" | python3 -c "import sys,json;print(json.load(sys.stdin)['ethAddress'])" 2>/dev/null)
on "$IDP" "pkill -f '[z]kd-demo/bin/node cia.js'; sleep 1; rm -f /tmp/cia_keyprobe_state.json"
[ -n "$ADDR" ] || { echo "IdP 주소를 못 읽었다 — idp 의 ~/zkd-demo/logs/cia_keyprobe.log"; exit 1; }
echo "IdP ethAddress $ADDR"

# 5. 배포: 폐기 체인에 캐노니컬 로그, 응용 체인에 그 로그를 가리키는 거울(revchain 네트워크의 주소만 바꿔 두 번)
MODE3_REV_CHAIN_RPC="http://127.0.0.1:$REV_PORT" CIA_ETH_ADDRESS="$ADDR" MODE3_CANONICAL_LOG_ADDRESS="" MODE3_CANONICAL_CHAIN_ID="" \
  npx hardhat run scripts/deploy_mode3_log.cjs --network revchain 2>&1 | grep -vE dotenv > "$LOGS/deploy_rev.log"
LOGADDR=$(grep -oE "CIA_LOG_ADDRESS=0x[0-9a-fA-F]+" "$LOGS/deploy_rev.log" | head -1 | cut -d= -f2)
[ -n "$LOGADDR" ] || { echo "폐기 체인 배포 실패 — $LOGS/deploy_rev.log"; exit 1; }
MODE3_REV_CHAIN_RPC="http://127.0.0.1:$APP_PORT" CIA_ETH_ADDRESS="$ADDR" MODE3_CANONICAL_LOG_ADDRESS="$LOGADDR" MODE3_CANONICAL_CHAIN_ID="$REV_CHAIN" \
  npx hardhat run scripts/deploy_mode3_log.cjs --network revchain 2>&1 | grep -vE dotenv > "$LOGS/deploy_app.log"
MIRROR=$(grep -oE "MODE3_MIRROR_ADDRESS=0x[0-9a-fA-F]+" "$LOGS/deploy_app.log" | head -1 | cut -d= -f2)
MIRRORS=$(grep -oE "CIA_MIRRORS=[0-9]+=0x[0-9a-fA-F]+" "$LOGS/deploy_app.log" | head -1 | cut -d= -f2-)
[ -n "$MIRROR" ] && [ -n "$MIRRORS" ] || { echo "응용 체인 거울 배포 실패 — $LOGS/deploy_app.log"; exit 1; }
echo "CIA_LOG_ADDRESS=$LOGADDR (chain $REV_CHAIN)  MODE3_MIRROR_ADDRESS=$MIRROR  CIA_MIRRORS=$MIRRORS"

# 6. 역할별 설정 파일(각 VM 에 자기 것만, 권한 600)과 기동
COMMON="CIA_LOG_ADDRESS=$LOGADDR
MODE3_MIRROR_ADDRESS=$MIRROR
CIA_MIRRORS=$MIRRORS
MODE3_WALLET_AGENT_ORIGIN=$WALLET_ORIGIN
MODE3_VERIFIER_ADDRESS=
MODE3_RP_FACTORY_ADDRESS=
MODE3_BIND_HOST=0.0.0.0"
put_env() { on "$1" "umask 077 && cat > ~/zkd-demo/role.env && chmod 600 ~/zkd-demo/role.env"; }
printf '%s\n' "$COMMON" "CIA_PORT=$IDP_PORT" "CIA_RPC_URL=http://$HOST:$REV_PORT" "CIA_CHAIN_RPCS=$APP_CHAIN=http://$HOST:$APP_PORT" "CIA_ADMIN_SECRET=$ADMIN" "CIA_ADMIN_OPEN=${ADMIN_OPEN:-1}" | put_env "$IDP"
printf '%s\n' "$COMMON" "MODE3_RP_PORT=$RP1_PORT" "MODE3_RP_NAME=zkONE" "MODE3_RP_PUBLIC_ORIGIN=http://$RP1:$RP1_PORT" "MODE3_CIA_URL=http://$IDP:$IDP_PORT" \
  "CIA_RPC_URL=http://$HOST:$APP_PORT" "MODE3_RELAYER_INDEX=0" | put_env "$RP1"
printf '%s\n' "$COMMON" "MODE3_RP_PORT=$RP2_PORT" "MODE3_RP_NAME=zkTWO" "MODE3_RP_PUBLIC_ORIGIN=http://$RP2:$RP2_PORT" "MODE3_CIA_URL=http://$IDP:$IDP_PORT" \
  "CIA_RPC_URL=http://$HOST:$APP_PORT" "MODE3_RELAYER_INDEX=1" "MODE3_ALLOWED_COUNTRIES=410,392" "MODE3_MIN_AGE=19" "MODE3_REQUIRE_DISCLOSURE=1" | put_env "$RP2"
start_remote() { # $1 호스트 $2 스크립트 $3 포트
  on "$1" "cd ~/zkd-demo && set -a && . ./role.env && set +a && { setsid nohup \$HOME/zkd-demo/bin/node $2 > logs/${2%.js}.log 2>&1 < /dev/null & }"
  for i in $(seq 1 40); do curl -s -m 2 -o /dev/null "http://$1:$3/mode3/health" && { echo "$2 up at http://$1:$3"; return 0; }; sleep 1; done
  echo "$2 at $1:$3 failed — $1 의 ~/zkd-demo/logs/${2%.js}.log"; exit 1
}
start_remote "$IDP" cia.js $IDP_PORT
: > "$LOGS/empty.env"
if [ "$WALLET_MODE" = "snap" ]; then
  # Snap 모드(2026-10-22): 에이전트는 증명·동기화만, 비밀은 MetaMask 의 Snap 안. 릴레이어 계정은 RP 둘(0·1)과 겹치지 않게 2. .env 는 읽지 않는다(DOTENV_CONFIG_PATH).
  DOTENV_CONFIG_PATH="$LOGS/empty.env" MODE3_WALLET_SECRETS=snap MODE3_SNAP_ID="local:http://localhost:$SNAP_PORT" MODE3_WALLET_PORT=$USER_PORT MODE3_WALLET_PUBLIC_ORIGIN="$WALLET_ORIGIN" \
    MODE3_CIA_URL="http://$IDP:$IDP_PORT" MODE3_RP_ORIGIN="http://$RP1:$RP1_PORT,http://$RP2:$RP2_PORT" MODE3_RELAYER_INDEX=2 MODE3_HEIGHT_GRID="${HEIGHT_GRID:-5}" \
    CIA_RPC_URL="http://127.0.0.1:$APP_PORT" MODE3_REV_CHAIN_RPC="http://127.0.0.1:$REV_PORT" CIA_LOG_ADDRESS="$LOGADDR" MODE3_MIRROR_ADDRESS="$MIRROR" \
    setsid nohup node mode3_wallet_agent.js > "$LOGS/wallet_agent.log" 2>&1 < /dev/null &
  (cd snap-mode3 && setsid nohup npm run serve > "$LOGS/snap_serve.log" 2>&1 < /dev/null &)
  timeout 40 bash -c "until ss -ltn | grep -q ':$SNAP_PORT '; do sleep 1; done" && echo "snap serve :$SNAP_PORT up" || { echo "snap serve failed — $LOGS/snap_serve.log"; exit 1; }
else
DOTENV_CONFIG_PATH="$LOGS/empty.env" MODE3_PK_CIA_X="" MODE3_PK_CIA_Y="" MODE3_HEIGHT_GRID="${HEIGHT_GRID:-5}" MODE3_DEMO_GENERATION="$(date +%s)" MODE3_WALLET_PORT=$USER_PORT MODE3_WALLET_PUBLIC_ORIGIN="$WALLET_ORIGIN" \
  MODE3_CIA_URL="http://$IDP:$IDP_PORT" MODE3_RP_ORIGIN="http://$RP1:$RP1_PORT,http://$RP2:$RP2_PORT" \
  CIA_RPC_URL="http://127.0.0.1:$APP_PORT" MODE3_REV_CHAIN_RPC="http://127.0.0.1:$REV_PORT" CIA_LOG_ADDRESS="$LOGADDR" MODE3_MIRROR_ADDRESS="$MIRROR" \
  setsid nohup node mode3_user_static.js > "$LOGS/user_static.log" 2>&1 < /dev/null &
fi
timeout 30 bash -c "until ss -ltn | grep -q ':$USER_PORT '; do sleep 1; done" && echo "지갑($WALLET_MODE) up at $WALLET_ORIGIN" || { echo "지갑($WALLET_MODE) failed — $LOGS/$([ "$WALLET_MODE" = snap ] && echo wallet_agent || echo user_static).log"; exit 1; }
start_remote "$RP1" mode3_rp.js $RP1_PORT
start_remote "$RP2" mode3_rp.js $RP2_PORT

# 7. RP 등록 대기(승인은 기본 수동)
HDR="X-CIA-Admin-Secret: $ADMIN"
rps_json() { curl -s -m 5 -H "$HDR" "http://$IDP:$IDP_PORT/cia/rps"; }
active() { curl -s -m 5 "http://$1/mode3/health" | python3 -c "import sys,json;print(json.load(sys.stdin).get('active'))" 2>/dev/null; }
N=0
for i in $(seq 1 30); do N=$(rps_json | python3 -c "import sys,json
try: print(len(json.load(sys.stdin).get('rps',[])))
except Exception: print(0)"); [ "$N" -ge 2 ] && break; sleep 1; done
if [ "${AUTO_APPROVE:-0}" = "1" ]; then
  for i in $(seq 1 60); do
    for arid in $(rps_json | python3 -c "import sys,json
try: [print(r['arid']) for r in json.load(sys.stdin).get('rps',[]) if r.get('status')=='pending']
except Exception: pass"); do printf -- "approve %s… -> " "${arid:0:10}"; curl -s -m 15 -X POST -H "$HDR" "http://$IDP:$IDP_PORT/cia/rps/$arid/approve" | python3 -c "import sys,json
try: d=json.load(sys.stdin); print(d.get('status') or list(d)[:2])
except Exception: print('(응답 없음)')"; done
    [ "$(active $RP1:$RP1_PORT)" = "True" ] && [ "$(active $RP2:$RP2_PORT)" = "True" ] && { echo "zkONE·zkTWO active"; break; }
    sleep 2
  done
else
  echo "RP 등록 $N 건 — 승인 대기(pending). http://$IDP:$IDP_PORT/admin 에서 승인하세요 (AUTO_APPROVE=1 이면 자동)."
fi

# 8. 요약
for u in "$IDP:$IDP_PORT" "127.0.0.1:$USER_PORT" "$RP1:$RP1_PORT" "$RP2:$RP2_PORT"; do printf -- "--- %s " "$u"; curl -s -m 10 "http://$u/mode3/health" | python3 -c "import sys,json;d=json.load(sys.stdin);print({k:d.get(k) for k in ('role','ok','status','secrets','registered','accounts','pendingRps','active') if d.get(k) is not None})"; done
printf -- "--- 체인 구성: "; curl -s -m 5 "http://$IDP:$IDP_PORT/cia/public_keys" | python3 -c "import sys,json;d=json.load(sys.stdin);print('캐노니컬 chainId', d.get('canonicalChainId'), '· 거울', [m.get('chainId') for m in d.get('mirrors',[])])"
echo "SPLIT_DONE $(date '+%H:%M:%S')"
echo "페이지: 사용자 $WALLET_ORIGIN/  zkONE http://$RP1:$RP1_PORT/ (관리자 /admin)  zkTWO http://$RP2:$RP2_PORT/  IdP 관리자 http://$IDP:$IDP_PORT/admin  계정 http://$IDP:$IDP_PORT/account"
if [ "$WALLET_MODE" = "snap" ]; then
  echo "Snap 모드: 브라우저에 MetaMask Flask 가 있어야 한다. 지갑 페이지 $WALLET_ORIGIN/ 에서 MetaMask 연결 → Snap(local:http://localhost:$SNAP_PORT) 설치/재연결."
  echo "         체인·IdP 가 새로 시작됐으므로 MetaMask 안의 옛 등록은 지갑 페이지의 'Snap 초기화' 로 지운 뒤 다시 등록할 것."
fi
