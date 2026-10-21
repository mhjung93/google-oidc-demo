#!/usr/bin/env bash
# Mode 3 라이브 데모(web 모드, RP 2개) 재시연 세트 — 2026-10-16. docs/MODE3_DEMO.md "브라우저 전용 사용자 페이지" 절의 기동 순서를 한 번에 돈다.
#   전부 내림 → 상태 파일 백업 → hardhat 새로 → 로그·거울 배포 → (번들 빌드) → IdP(:4100)·사용자 페이지(:5100)·zkONE(:3100)·zkTWO(:3101) 기동.
#   오리진은 모두 http://localhost 로 통일한다(페이지들이 서로를 이 주소로 가리킨다 — 브라우저도 localhost 주소로 열 것).
#   RP 는 기본으로 **승인하지 않는다**(데모 1단계 "승인"을 IdP 관리자 페이지에서 직접 보여 준다). AUTO_APPROVE=1 이면 자동 승인.
# 사용:  bash scripts/demo_web_reset.sh            # 기본
#        AUTO_APPROVE=1 bash scripts/demo_web_reset.sh
#        SKIP_BUILD=1 bash scripts/demo_web_reset.sh  # 번들(mode3/user/dist)을 다시 만들지 않는다
#        DEMO_LOG_DIR=~/mode3-logs bash scripts/demo_web_reset.sh   # 로그 위치(기본 /tmp/mode3-demo)
#        HEIGHT_GRID=100 bash scripts/demo_web_reset.sh  # 만료(max_height) 올림 단위(기본 5 — 데모에서 로그인마다 값이 달라지는 걸 보이려고. 코드 기본은 100, 2026-10-21)
#        ADMIN_OPEN=0 bash scripts/demo_web_reset.sh  # IdP 관리자 인증을 켠 채로 띄운다(기본은 끔 — CIA_ADMIN_OPEN=1, 데모 전용, 2026-10-21)
#        TWO_CHAINS=1 bash scripts/demo_web_reset.sh   # 폐기 체인 분리(V10): 캐노니컬 로그는 :8546(chainId 31338), 거울·팩토리·계정은 :8545
#                                                       (런북 "폐기 체인을 별도 노드로" 절과 같은 순서 — IdP 가 :8546 에 게시하고 :8545 거울로 중계한다)
# 주의: 이 스크립트가 내리는 것은 자기가 띄우는 종류의 프로세스(node cia.js 등, 명령줄이 정확히 일치하는 것)와 hardhat node 뿐이다.
#       .env 는 건드리지 않는다. idp_state.json(Mode 2)도 건드리지 않는다. cia_state.json 등 Mode 3 상태 파일은 .bak-시각 으로 옮긴다.
set -u
cd "$(dirname "$0")/.."
LOGS="${DEMO_LOG_DIR:-/tmp/mode3-demo}"; mkdir -p "$LOGS"
TS=$(date '+%Y%m%d-%H%M')
echo "RESET_START $(date '+%H:%M:%S')  (logs: $LOGS)"

# 0. 전부 내림
pkill -f '^node (cia|mode3_rp|mode3_wallet_agent|mode3_user_static)\.js$' 2>/dev/null
pkill -f '^bash scripts/run_mode3_rp2.sh' 2>/dev/null
pkill -f '[.]bin/hardhat node$' 2>/dev/null
pkill -f '[.]bin/hardhat node --port 8546$' 2>/dev/null   # TWO_CHAINS 의 폐기 체인 노드(지난 실행이 띄운 것)
sleep 2
for port in 4100 5100 3100 3101 8545 8546; do ss -ltn | grep -q ":$port " && echo "WARN :$port 가 아직 쓰이고 있다(다른 프로세스?) — 계속 진행"; done

# 1. 상태 파일 백업(새 체인과 맞지 않는 옛 상태)
for f in cia_state.json mode3_wallet_state.json mode3_wallet_rcl.json mode3_rp_logins.jsonl mode3_rp_registration.json mode3_rp2_registration.json mode3_rp2_logins.jsonl; do
  [ -e "$f" ] && mv "$f" "$f.bak-$TS" && echo "backup $f -> $f.bak-$TS"
done

# 2. 사용자 페이지 번들
if [ "${SKIP_BUILD:-0}" != "1" ]; then npm run user:build 2>&1 | grep -E "built|error" || { echo "build failed"; exit 1; }; fi

# 3. 체인(응용 체인 :8545, TWO_CHAINS 면 폐기 체인 :8546 도 — chainId 가 같으면 서명이 두 체인을 못 가르므로 31338)
TWO="${TWO_CHAINS:-0}"
setsid nohup npx hardhat node > "$LOGS/hardhat.log" 2>&1 < /dev/null &
timeout 40 bash -c 'until ss -ltn | grep -q ":8545 "; do sleep 1; done' && echo "hardhat :8545 up" || { echo "hardhat failed"; exit 1; }
if [ "$TWO" = "1" ]; then
  HARDHAT_CHAIN_ID=31338 setsid nohup npx hardhat node --port 8546 > "$LOGS/hardhat_rev.log" 2>&1 < /dev/null &
  timeout 40 bash -c 'until ss -ltn | grep -q ":8546 "; do sleep 1; done' && echo "revchain :8546 (chainId 31338) up" || { echo "revchain failed — $LOGS/hardhat_rev.log"; exit 1; }
fi

# 4. 로그·거울 배포 → 주소 3개
export CIA_ETH_ADDRESS="${CIA_ETH_ADDRESS:-0x19fA433ACfd5833A06325D8e815274aEd44B50Fa}"
if [ "$TWO" = "1" ]; then
  # 4a. 캐노니컬 로그를 폐기 체인에(스크립트는 거기에도 거울을 하나 배포하지만 쓰지 않는다 — 런북 2단계)
  npx hardhat run scripts/deploy_mode3_log.cjs --network revchain 2>&1 | grep -vE dotenv > "$LOGS/deploy_rev.log"
  LOGADDR=$(grep -oE "CIA_LOG_ADDRESS=0x[0-9a-fA-F]+" "$LOGS/deploy_rev.log" | head -1 | cut -d= -f2)
  [ -n "$LOGADDR" ] || { echo "revchain deploy failed — $LOGS/deploy_rev.log 확인"; exit 1; }
  # 4b. 거울만 응용 체인에(canonicalChainId=31338 을 가리킨다 — 런북 3단계)
  MODE3_CANONICAL_LOG_ADDRESS="$LOGADDR" MODE3_CANONICAL_CHAIN_ID=31338 npx hardhat run scripts/deploy_mode3_log.cjs --network localhost 2>&1 | grep -vE dotenv > "$LOGS/deploy.log"
  { echo "CIA_LOG_ADDRESS=$LOGADDR"; grep -oE "MODE3_MIRROR_ADDRESS=0x[0-9a-fA-F]+|CIA_MIRRORS=[0-9]+=0x[0-9a-fA-F]+" "$LOGS/deploy.log"; } > "$LOGS/demo_env.txt"
  [ "$(wc -l < "$LOGS/demo_env.txt")" -ge 3 ] || { echo "mirror deploy failed — $LOGS/deploy.log 확인"; exit 1; }
else
  npx hardhat run scripts/deploy_mode3_log.cjs --network localhost 2>&1 | grep -vE dotenv > "$LOGS/deploy.log"
  grep -oE "CIA_LOG_ADDRESS=0x[0-9a-fA-F]+|MODE3_MIRROR_ADDRESS=0x[0-9a-fA-F]+|CIA_MIRRORS=[0-9]+=0x[0-9a-fA-F]+" "$LOGS/deploy.log" > "$LOGS/demo_env.txt"
  [ -s "$LOGS/demo_env.txt" ] || { echo "deploy failed — $LOGS/deploy.log 확인"; exit 1; }
fi
cat "$LOGS/demo_env.txt"
set -a; . "$LOGS/demo_env.txt"; set +a

# 5. 공통 env(오리진 localhost 통일)
export CIA_ADMIN_SECRET="${CIA_ADMIN_SECRET:-admin123}" CIA_ADMIN_OPEN="${ADMIN_OPEN:-1}" CIA_CHAIN_RPCS="31337=http://127.0.0.1:8545" MODE3_VERIFIER_ADDRESS="" MODE3_RP_FACTORY_ADDRESS=""
export MODE3_HEIGHT_GRID="${HEIGHT_GRID:-5}"
export MODE3_WALLET_AGENT_ORIGIN="http://localhost:5100" MODE3_WALLET_PUBLIC_ORIGIN="http://localhost:5100" MODE3_RP_ORIGIN="http://localhost:3100,http://localhost:3101" MODE3_CIA_URL="http://localhost:4100"

# 6. 서버 넷
# CIA_RPC_URL 은 프로세스마다 준다(런북 4단계): IdP 는 캐노니컬 체인에 게시하고, 사용자 페이지·RP 는 응용 체인을 본다(사용자 페이지는 캐노니컬도 읽는다).
if [ "$TWO" = "1" ]; then IDP_RPC="http://127.0.0.1:8546"; REV_RPC="http://127.0.0.1:8546"; else IDP_RPC="http://127.0.0.1:8545"; REV_RPC="http://127.0.0.1:8545"; fi
CIA_RPC_URL="$IDP_RPC" setsid nohup node cia.js > "$LOGS/cia.log" 2>&1 < /dev/null &
timeout 40 bash -c 'until ss -ltn | grep -q ":4100 "; do sleep 1; done' && echo "IdP :4100 up" || { echo "IdP failed — $LOGS/cia.log"; exit 1; }
CIA_RPC_URL="http://127.0.0.1:8545" MODE3_REV_CHAIN_RPC="$REV_RPC" MODE3_DEMO_GENERATION="$(date +%s)" setsid nohup node mode3_user_static.js > "$LOGS/user_static.log" 2>&1 < /dev/null &
CIA_RPC_URL="http://127.0.0.1:8545" MODE3_RP_NAME="zkONE" MODE3_RP_PUBLIC_ORIGIN="http://localhost:3100" setsid nohup node mode3_rp.js > "$LOGS/rp1.log" 2>&1 < /dev/null &
CIA_RPC_URL="http://127.0.0.1:8545" MODE3_RP_NAME="zkTWO" MODE3_RP_PUBLIC_ORIGIN="http://localhost:3101" MODE3_REQUIRE_DISCLOSURE=1 setsid nohup bash scripts/run_mode3_rp2.sh > "$LOGS/rp2.log" 2>&1 < /dev/null &
timeout 60 bash -c 'until ss -ltn | grep -q ":5100 " && ss -ltn | grep -q ":3100 " && ss -ltn | grep -q ":3101 "; do sleep 1; done' && echo "user-static :5100 + zkONE :3100 + zkTWO :3101 up" || { echo "some server failed"; ss -ltn | grep -E ":(5100|3100|3101) "; exit 1; }

# 7. RP 등록 대기(승인은 기본 수동)
HDR="X-CIA-Admin-Secret: $CIA_ADMIN_SECRET"
rps_json() { curl -s -m 5 -H "$HDR" http://127.0.0.1:4100/cia/rps; }
active() { curl -s -m 5 "http://127.0.0.1:$1/mode3/health" | python3 -c "import sys,json;print(json.load(sys.stdin).get('active'))" 2>/dev/null; }
for i in $(seq 1 30); do N=$(rps_json | python3 -c "import sys,json
try: print(len(json.load(sys.stdin).get('rps',[])))
except Exception: print(0)"); [ "$N" -ge 2 ] && break; sleep 1; done
if [ "${AUTO_APPROVE:-0}" = "1" ]; then
  for i in $(seq 1 60); do
    for arid in $(rps_json | python3 -c "import sys,json
try: [print(r['arid']) for r in json.load(sys.stdin).get('rps',[]) if r.get('status')=='pending']
except Exception: pass"); do printf -- "approve %s… -> " "${arid:0:10}"; curl -s -m 15 -X POST -H "$HDR" "http://127.0.0.1:4100/cia/rps/$arid/approve" | python3 -c "import sys,json
try: d=json.load(sys.stdin); print(d.get('status') or list(d)[:2])
except Exception: print('(응답 없음)')"; done
    [ "$(active 3100)" = "True" ] && [ "$(active 3101)" = "True" ] && { echo "zkONE·zkTWO active"; break; }
    sleep 2
  done
else
  echo "RP 등록 $N 건 — 승인 대기(pending). http://localhost:4100/admin 에서 승인하세요 (AUTO_APPROVE=1 이면 자동)."
fi

# 8. 요약
for p in 4100 5100 3100 3101; do printf -- "--- :%s " "$p"; curl -s -m 10 "http://127.0.0.1:$p/mode3/health" | python3 -c "import sys,json;d=json.load(sys.stdin);print({k:d.get(k) for k in ('role','ok','status','secrets','registered','accounts','pendingRps','active') if d.get(k) is not None})"; done
printf -- "--- 체인 구성: "; curl -s -m 5 http://127.0.0.1:4100/cia/public_keys | python3 -c "import sys,json;d=json.load(sys.stdin);print('캐노니컬 chainId', d.get('canonicalChainId'), '· 거울', [m.get('chainId') for m in d.get('mirrors',[])])"
echo "RESET_DONE $(date '+%H:%M:%S')"
echo "페이지: 사용자 http://localhost:5100/  zkONE http://localhost:3100/ (관리자 /admin)  zkTWO http://localhost:3101/  IdP 관리자 http://localhost:4100/admin  계정 http://localhost:4100/account"
