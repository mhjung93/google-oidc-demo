#!/usr/bin/env bash
# Mode 3 VM 분리 데모 기동(2026-10-20). 체인 두 개(응용 :8547 chainId 31339, 폐기 :8548 chainId 31340)와 사용자 페이지(:5200)는 이 VM,
# IdP·zkONE·zkTWO 는 각자의 VM 에서 돈다. 이 VM 의 라이브 데모(:8545/:8546/:4100/:5100/:3100/:3101)는 건드리지 않는다.
# 전제: 이 VM 에서 세 VM 으로 키 ssh 가 되고, 각 VM 의 ~/zkd-demo 에 코드·node_modules·Node 실행 파일이 있다(없거나 코드를 고쳤으면 SYNC=1).
# 사용:  bash scripts/demo_split_start.sh                  # 새 체인으로 전부 다시 띄움(RP 승인은 IdP 관리자 페이지에서 수동)
#        AUTO_APPROVE=1 bash scripts/demo_split_start.sh   # RP 자동 승인
#        SYNC=1 bash scripts/demo_split_start.sh           # 먼저 코드·의존성·Node 를 세 VM 에 다시 보냄
#        bash scripts/demo_split_start.sh stop             # 분리 데모만 전부 내림
#        HEIGHT_GRID=100 bash scripts/demo_split_start.sh  # 만료(max_height) 올림 단위(기본 5 — 데모용. 코드 기본은 100, 2026-10-21)
#        TTL_BLOCKS=300 bash scripts/demo_split_start.sh  # (snap·passkey-web 모드) 세션 수명 블록 수(기본 5 — 2026-11-11 사용자 요청: 자연 만료를 시연한다. 코드 기본은 300)
#        REVOKE_PUBLISH_AFTER=0 bash scripts/demo_split_start.sh  # (2026-11-12 시연 Race (2)) IdP 가 스냅의 세션 폐기를 받은 뒤 이 블록 수가 지나면 스스로 게시·중계(기본 3, 0 = 끔 — 관리자 "게시"·하트비트만)
#        TRACE=0 bash scripts/demo_split_start.sh  # (2026-11-26, zkwrapper) 추적 기록 등록부·감사자 프로세스를 띄우지 않는다(기본 켜짐 — 서비스마다 첫 로그인에 기록을 남긴다)
#        DEMO_RACE=0 bash scripts/demo_split_start.sh  # (snap 모드) 스냅 에이전트의 블록 진행 시연(/wallet/demo/mine, 기본 켜짐 — RP 출금의 "보내기 전에 멈춤")
#        WALLET_MODE=snap bash scripts/demo_split_start.sh  # Snap 모드(2026-10-22): 이 VM 의 지갑 자리에 에이전트(:5100, MODE3_WALLET_SECRETS=snap)+Snap 서버(:8082). 포트 5100 은 Snap 이 허용하는
#                                                          # 지갑 오리진(snap-mode3/src/index.js)이라 바꿀 수 없다 — 한 머신 데모(:5100)와 동시에 못 띄운다. scripts/demo_split_snap_reset.sh 가 이 값을 넣어 부른다(web 모드 리셋은 scripts/demo_split_reset.sh).
#        ADMIN_OPEN=1 bash scripts/demo_split_start.sh     # IdP 관리자 인증을 끈 채로(2026-11-05 부터 기본은 켬 — 관리자 페이지 비밀번호 idp; RP 관리자는 zkone·zktwo)
#        BLOCKSCOUT_RESET=0 bash scripts/demo_split_start.sh  # 로컬 Blockscout(.local/blockscout) 색인 초기화를 건너뛴다(기본은 체인을 새로 만들 때 함께 비운다, 2026-11-17)
#        BLOCKSCOUT_VERIFY=0 bash scripts/demo_split_start.sh  # 컨트랙트 자동 검증 감시자(scripts/blockscout_verify_watch.mjs)를 띄우지 않는다(기본은 띄운다, 2026-11-18 — 로그는 $LOGS/blockscout_verify.log)
#        BLOCKSCOUT_PROJECT=이름 bash scripts/demo_split_start.sh  # Blockscout 의 compose 프로젝트 이름(기본 zkid-blockscout — 화면에 보이는 :4000 스택). 초기화(down -v·up -d)가 이 이름에 걸린다
#        BLOCKSCOUT_URL=주소 bash scripts/demo_split_start.sh  # 사용자 페이지(web·passkey-web)의 증명 기록이 거래 링크를 거는 탐색기 주소(기본 http://127.0.0.1:4000, Blockscout 가 없으면 링크 없음)
#        ISSUE_AUTH=code bash scripts/demo_split_start.sh  # 발급 인증 정책(기본은 WALLET_MODE 에 따른다 — snap 은 CIA_ISSUE_AUTH=code, web 은 key, 2026-10-23: web 코어는
#                                                           # auth_code 를 보내지 않으므로 code 로 켜면 로그인이 막힌다). code 면 로그인 때 지갑 팝업이 연 IdP 인증 창(uid·비밀번호·auid)의 1회용 코드가
#                                                           # 있어야 발급한다(2026-10-22). key 면 옛 방식(서명만) — CIA_DEMO_ACCOUNTS 는 그대로 미설정(가입(POST /cia/signup)만 쓴다)
#                                                           # 2026-11-19(스펙 passkey-proof-login): passkey-web 의 기본도 key — 등록된 뒤의 로그인은 인증 창 없이 패스키 증명만으로 하고,
#                                                           # zkIdP 페이지에 "패스키로 로그인" 이 보인다. passkey-web 을 ISSUE_AUTH=code 로 띄우면 11-18 까지의 동작(로그인마다 인증 창)이다
#        RP1_GOOGLE_CLIENT_ID=… RP2_GOOGLE_CLIENT_ID=… bash scripts/demo_split_start.sh  # passkey-web 의 Google 로그인(실제 OIDC, 2026-11-19): 서비스마다 다른 Google 클라이언트 ID(없으면 공유 ID).
#                                                          # Google 콘솔에서 그 클라이언트의 "승인된 리디렉션 URI" 에 https://127.0.0.1:5100/google-relay 를 넣어 둬야 한다
#        PLAIN_OIDC=0 bash scripts/demo_split_start.sh    # 일반 OIDC(비교용 — zkIdP 가 uid·rid 를 그대로 내는 보통의 OIDC 로그인, 서비스 로그인 창의 "일반 OIDC · 비교용" 버튼) 끔.
#                                                          # 기본은 passkey-web 이고 Google 클라이언트 ID 가 없을 때만 켬(2026-11-20 — Google 이 있으면 일반 OIDC 장면은 Google 로 보인다). 켜려면 PLAIN_OIDC=1
#        OIDC=0 bash scripts/demo_split_start.sh          # Google(OIDC 래퍼) 끔. 기본은 켬(2026-10-26): IdP 에 MODE3_OIDC_CLIENT_ID 를 넘긴다 — 값은 환경변수 MODE3_OIDC_CLIENT_ID,
#                                                          # 없으면 이 VM .env 의 GOOGLE_CLIENT_ID(Mode 1 공유 ID, 출력하지 않는다). Google 콘솔 승인 오리진에 http://localhost:5100 이 있어야 한다.
#        (2026-11-09 연결 로그인) 브라우저는 IdP 를 http://localhost:4100 으로 연다 — 이 VM 의 SSH 터널(127.0.0.1:4100 → IdP VM:4100)이다. Google 은 http 원본으로
#                                                          # localhost 만 받으므로 /user 의 "Google 계정 연결"·인증 창의 Google 인증이 이 주소에서만 된다. Google 콘솔 승인 오리진에 http://localhost:4100 도 넣는다.
#                                                          # 지갑의 MODE3_CIA_URL·RP 의 MODE3_CIA_BROWSER_URL(페이지 링크) 이 이 주소다(RP 의 서버 간 호출은 VM 주소). 기본은 snap 모드만 켬,
#                                                          # SPLIT_IDP_TUNNEL=0/1 로 바꾼다(0 이면 VM 주소 — Google 연결은 안 된다).
#                                                          # :4100 을 한 머신 데모 IdP 가 쓰고 있으면 중단한다.
#        (2026-11-10 RP 소셜 로그인) snap 모드 기본 SPLIT_RP_TUNNEL=1 — 이 VM 에 localhost:3100→zkONE, localhost:3101→zkTWO 터널. RP 공개 주소·지갑의 RP 오리진이 localhost 가 된다
#                                                          # (Google 은 http 원본으로 localhost 만). Google 클라이언트 ID(IdP 래퍼와 같은 값)와 네이버 ID·Secret(환경변수 또는 이 VM .env 의 MODE3_NAVER_CLIENT_ID·_SECRET)은
#                                                          # RP role.env 에만, 출력은 on/off 만. 네이버 Callback: http://localhost:3100/api/rp/naver/callback, http://localhost:3101/api/rp/naver/callback.
#                                                          # Google 콘솔 승인된 원본: http://localhost:3100, http://localhost:3101. RP 공개 주소가 바뀌면 RP 가 스스로 새로 등록한다(IdP 승인 다시).
#        WALLET_MODE=passkey-web bash scripts/demo_split_start.sh  # (2026-11-17) 설치 없는 패스키 모드: 호스트 PC 의 정적 서버(:5100, https)가 지갑. 이름 주소(wallet·idp·zkone·zktwo.zkd.test)와 데모 CA 인증서를
#                                                          # VM 세 곳에 배포한다. 처음이면 먼저 bash scripts/zkd_tls_setup.sh(sudo) 뒤 Chrome 재시작. 터널은 강제로 끈다. stop 도 같은 WALLET_MODE 로 부른다.
#        WALLET_MODE=zkwrapper ZKWRAPPER_GOOGLE_CLIENT_ID=… bash scripts/demo_split_start.sh  # (2026-11-20 스펙 zkwrapper) 별도 IdP 없이 zkWrapper: 이 PC 의 한 서버(:5100, https://zkwrapper.zkd.test — 2026-11-25 전에는 wallet.zkd.test)가
#                                                          # 지갑 화면과 발급(Google 토큰 → 세션 토큰)을 함께 맡는다. IdP VM 에는 아무것도 띄우지 않는다. passkey-web 과 같은 데모 CA·hosts 가 필요하고,
#                                                          # 래퍼 전용 Google 클라이언트 ID(서비스의 ID 와 달라야 한다 — 같으면 멈춘다)의 승인된 리디렉션 URI 에 https://127.0.0.1:5100/google-relay 가 있어야 한다.
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
# zkwrapper(2026-11-20 스펙 zkwrapper): 화면·인증서·hosts 규칙은 passkey-web 과 같다 — 모드는 passkey-web 으로 두고 ZW=1 표시로 다른 점만 가른다(지갑 서버 = 발급 서버, IdP VM 없음).
ZW=0; [ "$WALLET_MODE" = zkwrapper ] && { ZW=1; WALLET_MODE=passkey-web; }
ZW_DIR=".local/zkwrapper"   # zkWrapper 의 상태·열쇠 — 저장소 루트의 cia_keys.json(한 머신 데모 IdP)과 섞이지 않게 따로 둔다(.local 은 git 무시)
case "$WALLET_MODE" in web) USER_PORT=5200 ;; snap|passkey) USER_PORT=5100 ;; passkey-web) USER_PORT=5100 ;; *) echo "WALLET_MODE 는 web·snap·passkey·passkey-web 중 하나: $WALLET_MODE"; exit 1 ;; esac
# passkey(2026-11-17, 스펙 2026-11-17-mode3-passkey-mode): 지갑은 snap 처럼 에이전트(:5100)지만 MetaMask·스냅 서버가 없다. 패스키는 localhost 의 어느 포트 페이지든
# 부를 수 있으므로(§2) 브라우저용 IdP·RP 주소는 터널을 127.0.0.1 로 연다 — IP 오리진에서는 WebAuthn 이 동작하지 않는다. 대신 RP 소셜 로그인(localhost 전용)은 쓸 수 없다.
# passkey-web(2026-11-17, 스펙 2026-11-17-mode3-passkey-web): 에이전트 없이 호스트 PC 의 정적 서버(web 분기와 같은 서버)가 https 로 지갑 자리를 맡는다.
AGENT_MODE=$([ "$WALLET_MODE" = web ] || [ "$WALLET_MODE" = passkey-web ] && echo 0 || echo 1)
# 일반 OIDC — 비교용(2026-11-19 스펙 oidc-comparison C1·C7): zkIdP 가 sub = uid·aud = rid 인 보통의 OIDC 공급자 노릇도 하고(CIA_PLAIN_OIDC), 서비스가 그 로그인을 받는다(MODE3_RP_ZKOIDC).
# passkey-web 에서만 기본으로 켠다 — PLAIN_OIDC=0 으로 끄고, 다른 모드는 PLAIN_OIDC=1 로 켠다.
# 2026-11-20(사용자 결정): "일반 OIDC" 장면은 실제 Google 로 보인다 — 서비스의 Google 로그인이 켜지는 구성(Google 클라이언트 ID 가 있다)이면 zkIdP 의 비교용 일반 OIDC 는
# 기본으로 끈다(로그인 창에 "zkIdP 로 로그인" 과 "Google 로 로그인 (일반 OIDC)" 둘만 남는다). 예비로 다시 켜려면 PLAIN_OIDC=1. 아래 판정은 값이 있는지만 본다(출력하지 않는다).
GOOGLE_ID_SET=0
if [ -n "${RP1_GOOGLE_CLIENT_ID:-}${RP2_GOOGLE_CLIENT_ID:-}" ] || { [ "${OIDC:-1}" != 0 ] && { [ -n "${MODE3_OIDC_CLIENT_ID:-}" ] || grep -qs '^GOOGLE_CLIENT_ID=.' .env; }; }; then GOOGLE_ID_SET=1; fi
PLAIN_OIDC="${PLAIN_OIDC:-$([ "$WALLET_MODE" = passkey-web ] && [ "$GOOGLE_ID_SET" != 1 ] && echo 1 || echo 0)}"
[ "$ZW" = 1 ] && PLAIN_OIDC=0   # zkWrapper 에는 일반 OIDC(/oidc)가 없다 — 비교 장면은 서비스의 Google 로그인으로 보인다
SCHEME=http; ZKD_CA_DIR="${ZKD_CA_DIR:-.local/zkd-ca}"; CACERT=()
PEER_HOST=$([ "$WALLET_MODE" = passkey ] && echo 127.0.0.1 || echo localhost)
if [ "$WALLET_MODE" = "snap" ]; then [ -d snap-mode3/node_modules ] && [ -f snap-mode3/dist/bundle.js ] || { echo "BLOCKED: snap-mode3/node_modules 또는 dist/bundle.js 가 없다 — cd snap-mode3 && npm install && npm run build"; exit 1; }; fi
APP_PORT=8547 APP_CHAIN=31339 REV_PORT=8548 REV_CHAIN=31340 IDP_PORT=4100 RP1_PORT=3100 RP2_PORT=3101 SNAP_PORT=8082
LOGS="${DEMO_LOG_DIR:-/tmp/mode3-split}"; mkdir -p "$LOGS"
# 로컬 Blockscout(2026-11-18 스펙 blockscout-auto-verify): 화면에 보이는 스택의 compose 프로젝트 이름과, 자동 검증 감시자의 pid 파일.
BS_PROJECT="${BLOCKSCOUT_PROJECT:-zkid-blockscout}"
BS_VERIFY_PID="$LOGS/blockscout_verify.pid"; BS_VERIFY_RCL_PID="$LOGS/blockscout_verify_rcl.pid"
TS=$(date '+%Y%m%d-%H%M')
ADMIN="${CIA_ADMIN_SECRET:-idp}"   # IdP 관리자 페이지 비밀번호(2026-11-05, 사용자 요청: 쉽게 idp)
WALLET_ORIGIN="http://localhost:$USER_PORT"
TUNNEL_SPEC="-L 127.0.0.1:$IDP_PORT:127.0.0.1:$IDP_PORT"   # 2026-11-09: 브라우저용 IdP 주소(localhost:4100) 터널 — stop_local 이 이 명령줄로 찾는다
# 기본은 snap 모드에서만 켠다(리뷰 Minor 7) — web 모드 지갑(:5200)은 연결 로그인을 쓰지 않아(인증 창 method 를 모른다) 한 머신 IdP(:4100)와 같이 띄울 수 있게 둔다.
SPLIT_IDP_TUNNEL="${SPLIT_IDP_TUNNEL:-$AGENT_MODE}"
if [ "$SPLIT_IDP_TUNNEL" != 0 ]; then IDP_UI="http://$PEER_HOST:$IDP_PORT"; else IDP_UI="http://$IDP:$IDP_PORT"; fi
# RP 터널(2026-11-10 RP 소셜 로그인): 브라우저가 zkONE·zkTWO 를 localhost 로 연다 — RP 의 Google(GIS)·네이버 콜백이 localhost 원본에서만 된다. 기본은 snap 모드만.
RP1_TUNNEL="-L 127.0.0.1:$RP1_PORT:127.0.0.1:$RP1_PORT"; RP2_TUNNEL="-L 127.0.0.1:$RP2_PORT:127.0.0.1:$RP2_PORT"
SPLIT_RP_TUNNEL="${SPLIT_RP_TUNNEL:-$AGENT_MODE}"
if [ "$SPLIT_RP_TUNNEL" != 0 ]; then RP1_UI="http://$PEER_HOST:$RP1_PORT"; RP2_UI="http://$PEER_HOST:$RP2_PORT"; else RP1_UI="http://$RP1:$RP1_PORT"; RP2_UI="http://$RP2:$RP2_PORT"; fi
# passkey-web: 브라우저는 hosts 의 이름으로 바로 간다 — 터널을 강제로 끄고(R-14) 주소는 https 이름(포트 포함, R-1). 서버 간·curl 은 IP 로 부른다(인증서 IP SAN).
if [ "$WALLET_MODE" = passkey-web ]; then
  SCHEME=https; SPLIT_IDP_TUNNEL=0; SPLIT_RP_TUNNEL=0; CACERT=(--cacert "$ZKD_CA_DIR/ca.crt")
  WALLET_ORIGIN="https://wallet.zkd.test:$USER_PORT"; IDP_UI="https://idp.zkd.test:$IDP_PORT"
  RP1_UI="https://zkone.zkd.test:$RP1_PORT"; RP2_UI="https://zktwo.zkd.test:$RP2_PORT"
fi
# zkwrapper 는 지갑이 아니라 래퍼 서버라 이름이 다르다(2026-11-25 사용자 요청). passkey-web 은 wallet.zkd.test 그대로다. 패스키는 이름에 묶이므로 두 모드의 패스키도 다르다.
[ "$ZW" = 1 ] && WALLET_ORIGIN="https://zkwrapper.zkd.test:$USER_PORT"
[ "$ZW" = 1 ] && IDP_UI="$WALLET_ORIGIN"   # zkwrapper: 사람이 여는 발급자 화면(운영자·관리자)은 지갑과 같은 서버다
# 서버끼리 부르는 발급자 주소 — 서비스 VM 의 MODE3_CIA_URL, 이 스크립트의 curl. zkwrapper 는 이 PC 의 zkWrapper(인증서 IP SAN 에 $HOST 가 있다).
CIA_SRV="$SCHEME://$IDP:$IDP_PORT"; [ "$ZW" = 1 ] && CIA_SRV="$SCHEME://$HOST:$USER_PORT"
on() { local h="$1"; shift; ssh -o BatchMode=yes -o ConnectTimeout=5 "$U@$h" "$@"; }

# Blockscout 자동 검증 감시자는 포트를 듣지 않아 아래 포트 목록으로는 못 찾는다 — pid 파일의 pid 를, 명령줄이 감시자일 때만 내린다(B10).
stop_verify_watch() {
  [ -f "$BS_VERIFY_PID" ] || return 0
  pid=$(cat "$BS_VERIFY_PID" 2>/dev/null)
  case "$pid" in ''|*[!0-9]*) ;; *) tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -qF -- "blockscout_verify_watch.mjs" && kill "$pid" && echo "stop blockscout_verify_watch (pid $pid)" ;; esac
  rm -f "$BS_VERIFY_PID"
}
stop_verify_watch_rcl() { BS_VERIFY_PID="$BS_VERIFY_RCL_PID" stop_verify_watch; }   # 폐기 체인의 감시자(2026-11-25) — pid 파일만 다르다
# 이 VM 쪽은 포트 주인 중 명령줄이 우리 것과 맞는 것만 내린다(라이브 데모와 명령줄이 같은 사용자 페이지는 포트로 가른다).
stop_local() {
  # passkey-web 의 정적 서버(:5100)는 그 모드일 때만 찾는다 — 다른 모드로 부르면 한 머신 데모의 :5100 정적 서버를 건드리지 않는다.
  STOP_EXTRA=""; [ "$WALLET_MODE" = passkey-web ] && STOP_EXTRA="5100:mode3_user_static.js 5100:mode3_zkwrapper.js"   # zkwrapper 도 이 모드다(ZW) — 어느 쪽으로 띄웠든 5100 의 우리 서버를 내린다
  for spec in "$APP_PORT:chain.config.cjs" "$REV_PORT:chain.config.cjs" "5200:mode3_user_static.js" "5100:mode3_wallet_agent.js" "$SNAP_PORT:mm-snap serve" "$IDP_PORT:$TUNNEL_SPEC" "$RP1_PORT:$RP1_TUNNEL" "$RP2_PORT:$RP2_TUNNEL" $STOP_EXTRA; do
    port="${spec%%:*}"; want="${spec#*:}"
    for pid in $(ss -ltnp 2>/dev/null | grep ":$port " | grep -oE "pid=[0-9]+" | cut -d= -f2 | sort -u); do
      tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -qF -- "$want" && kill "$pid" && echo "stop :$port (pid $pid)"
    done
  done
  # 감사자 프로세스(2026-11-26 추적 기록, :5300) — 명령줄이 우리 것일 때만 내린다
  for pid in $(ss -ltnp 2>/dev/null | grep ":${AUDITOR_PORT:-5300} " | grep -oE "pid=[0-9]+" | cut -d= -f2 | sort -u); do
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -qF -- "mode3_auditors.js" && kill "$pid" && echo "stop :${AUDITOR_PORT:-5300} (pid $pid)"
  done
  stop_verify_watch; stop_verify_watch_rcl
}
# VM 쪽 패턴의 [z] 는 pkill 이 자기를 부른 원격 셸을 잡지 않게 하는 것이다.
# 원격 기동은 `{ 명령 & }` 로 감싼다 — `a && b &` 로 쓰면 목록 전체가 백그라운드 서브셸이 되어 ssh 출력을 쥔 채 남고, ssh 가 끝나지 않는다.
stop_remote() {
  [ "$ZW" = 1 ] || on "$IDP" "pkill -f '[z]kd-demo/bin/node cia.js' && echo 'stop IdP ($IDP)' || true"   # zkwrapper: IdP VM 을 쓰지 않는다(최종 검토 M-4)
  for h in "$RP1" "$RP2"; do on "$h" "pkill -f '[z]kd-demo/bin/node mode3_rp.js' && echo 'stop RP ($h)' || true"; done
}
if [ "${1:-}" = "stop" ]; then stop_remote; stop_local; exit 0; fi
# 사전 검사(zkwrapper, 2026-11-20 스펙 §10 C2): 래퍼 전용 Google 클라이언트 ID 가 있어야 하고 서비스의 ID 와 달라야 한다 — 같으면 서비스가 자기 요청 키의 nonce 로 사용자의
# 토큰을 받아 낼 수 있다. 값은 출력하지 않는다. 서비스 ID 는 RP1·RP2_GOOGLE_CLIENT_ID, 없으면 .env 의 GOOGLE_CLIENT_ID(공유 ID — 서비스에 그것이 간다).
if [ "$ZW" = 1 ]; then
  [ -n "${ZKWRAPPER_GOOGLE_CLIENT_ID:-}" ] || { echo "BLOCKED: zkwrapper 는 래퍼 전용 Google 클라이언트 ID 가 필요하다 — ZKWRAPPER_GOOGLE_CLIENT_ID=… (서비스의 ID 와 다른 것)"; exit 1; }
  # 서비스가 실제로 받는 공유 ID 와 같은 식이다(아래 oidc_client_id·RP_GOOGLE_LINE): 셸의 MODE3_OIDC_CLIENT_ID 가 먼저, 없으면 .env 의 GOOGLE_CLIENT_ID. OIDC=0 이면 공유 ID 를 주지 않는다(최종 검토 I-2 b).
  _shared=""; [ "${OIDC:-1}" != 0 ] && _shared="${MODE3_OIDC_CLIENT_ID:-$( [ -f .env ] && sed -n 's/^GOOGLE_CLIENT_ID=//p' .env | head -n1 | tr -d '\r"'"'" )}"
  ZW_DENY="$(printf '%s\n' "${RP1_GOOGLE_CLIENT_ID:-$_shared}" "${RP2_GOOGLE_CLIENT_ID:-$_shared}" | awk 'NF' | sort -u | paste -sd, -)"; unset _shared
  printf '%s\n' "${ZW_DENY//,/$'\n'}" | grep -qxF -- "$ZKWRAPPER_GOOGLE_CLIENT_ID" && { echo "BLOCKED: ZKWRAPPER_GOOGLE_CLIENT_ID 가 서비스(zkONE·zkTWO)의 Google 클라이언트 ID 와 같다 — 래퍼 전용 ID 를 따로 만든다"; exit 1; }
fi
# 사전 검사(passkey-web, 2026-11-17): 데모 CA·hosts 가 없으면 아무것도 내리기 전에 멈춘다 — 라이브 데모를 건드리지 않는다. 번들도 여기서 만든다(R-14, 옛 번들로 뜨는 것이 가장 흔한 실패).
if [ "$WALLET_MODE" = passkey-web ]; then
  [ -f "$ZKD_CA_DIR/ca.crt" ] && [ -f "$ZKD_CA_DIR/ca.key" ] \
    || { echo "BLOCKED: 먼저 bash scripts/zkd_tls_setup.sh (데모 CA 가 없다 — 처음 한 번, 끝나면 Chrome 재시작). ZKD_CA_DIR=$ZKD_CA_DIR"; exit 1; }
  # CA 의 이름 제약 망(zkd_ca_create 와 같은 openssl 출력)이 세 VM 주소를 덮는지 본다 — 벗어나면 Chrome 이 그 VM 인증서를 거부한다(R-4). 127.0.0.0/8 은 제외.
  CA_NET=$(openssl x509 -noout -text -in "$ZKD_CA_DIR/ca.crt" 2>/dev/null | grep -oE 'IP:[0-9.]+/255\.255\.255\.0' | grep -v '^IP:127\.' | head -n1 | sed 's/^IP://; s#/.*##')
  . scripts/zkd_tls_lib.sh
  [ "$ZW" = 1 ] || VMS_ALL=("$IDP" "$RP1" "$RP2"); [ "$ZW" = 1 ] && VMS_ALL=("$RP1" "$RP2")   # zkwrapper: IdP VM 을 쓰지 않는다(M-4)
  for vm_ip in "${VMS_ALL[@]}"; do
    zkd_ip_valid "$vm_ip" || { echo "BLOCKED: SPLIT_*_IP 값이 IPv4 주소가 아니다: $vm_ip"; exit 1; }
    zkd_ip_in_net24 "$vm_ip" "$CA_NET" \
      || { echo "BLOCKED: VM 주소 $vm_ip 가 데모 CA 의 이름 제약 망(${CA_NET:-없음}/24) 밖이다 — ZKD_DEMO_NET 을 맞춰 CA 를 새로 만들고(bash scripts/zkd_tls_setup.sh) Chrome 에 다시 등록한다"; exit 1; }
  done
  # 이름이 hosts 에서 지금 주소로 풀려야 한다 — 옛 주소면 브라우저가 엉뚱한 VM 으로 간다
  [ "$ZW" = 1 ] || PAIRS=("127.0.0.1=wallet.zkd.test" "$IDP=idp.zkd.test" "$RP1=zkone.zkd.test" "$RP2=zktwo.zkd.test"); [ "$ZW" = 1 ] && PAIRS=("127.0.0.1=zkwrapper.zkd.test" "$RP1=zkone.zkd.test" "$RP2=zktwo.zkd.test")
  for pair in "${PAIRS[@]}"; do
    have_ip=$(getent hosts "${pair#*=}" | awk 'NR==1 { print $1 }')
    [ -n "$have_ip" ] \
      || { echo "BLOCKED: ${pair#*=} 가 /etc/hosts 에 없다 — 먼저 bash scripts/zkd_tls_setup.sh"; exit 1; }
    [ "$have_ip" = "${pair%%=*}" ] \
      || { echo "BLOCKED: ${pair#*=} 가 ${pair%%=*} 가 아니다(현재 $have_ip) — bash scripts/zkd_tls_setup.sh 를 다시 돌린다. 그래도 같으면 setup 은 블록 밖의 옛 줄은 지우지 않고 경고만 하므로 /etc/hosts 에서 블록 밖의 옛 ${pair#*=} 줄을 직접 지우세요"; exit 1; }
  done
  ZKD_CA_DIR="$(cd "$ZKD_CA_DIR" && pwd)"; CACERT=(--cacert "$ZKD_CA_DIR/ca.crt")
  { node scripts/build_user_app.mjs && node scripts/build_attr_tool.mjs; } > "$LOGS/build_bundles.log" 2>&1 || { echo "BLOCKED: 번들 빌드 실패 — $LOGS/build_bundles.log"; exit 1; }
fi
echo "SPLIT_START $(date '+%H:%M:%S')  (logs: $LOGS)"

# 0. 내림
stop_remote; stop_local; sleep 2
for p in $APP_PORT $REV_PORT $USER_PORT; do ss -ltn | grep -q ":$p " && { echo "ABORT :$p 를 다른 프로세스가 쓰고 있다"; exit 1; }; done
if [ "$SPLIT_IDP_TUNNEL" != 0 ] && ss -ltn | grep -q ":$IDP_PORT "; then echo "ABORT :$IDP_PORT 를 다른 프로세스(한 머신 데모 IdP?)가 쓰고 있다 — IdP 터널을 열 수 없다(SPLIT_IDP_TUNNEL=0 이면 터널 없이)"; exit 1; fi
if [ "$SPLIT_RP_TUNNEL" != 0 ]; then for p in $RP1_PORT $RP2_PORT; do ss -ltn | grep -q ":$p " && { echo "ABORT :$p 를 다른 프로세스(한 머신 데모 RP?)가 쓰고 있다 — RP 터널을 열 수 없다(SPLIT_RP_TUNNEL=0 이면 터널 없이)"; exit 1; }; done; fi

# 1. (선택) 코드·의존성·Node 다시 보내기 — 서버가 읽는 것만. 비밀·상태 파일, .env, ptau, 문서는 보내지 않는다.
if [ "${SYNC:-0}" = "1" ]; then
  FILES="package.json package-lock.json cia.js mode3_rp.js lib mode3 artifacts build/mode3/pi_cred_vkey.json build/mode3/pi_idp_vkey.json build/mode3/pi_cred_final.zkey build/mode3/pi_idp_final.zkey build/mode3/pi_cred_js/pi_cred.wasm build/mode3/pi_idp_js/pi_idp.wasm node_modules"
  NODE_BIN="$(command -v node)"
  [ "$ZW" = 1 ] || SYNC_VMS=("$IDP" "$RP1" "$RP2"); [ "$ZW" = 1 ] && SYNC_VMS=("$RP1" "$RP2")
  for h in "${SYNC_VMS[@]}"; do
    on "$h" 'mkdir -p ~/zkd-demo/bin ~/zkd-demo/logs' && rsync -aR -e "ssh -o BatchMode=yes" $FILES "$U@$h:zkd-demo/" \
      && rsync -a -e "ssh -o BatchMode=yes" "$NODE_BIN" "$U@$h:zkd-demo/bin/node" && echo "sync $h ok" || { echo "sync $h failed"; exit 1; }
  done
fi

# 1b. (passkey-web) 서버 인증서 넷을 데모 CA 로 만들고 VM 에 보낸다(R-4·R-15). 개인키는 600 으로 두고 어디에도 출력하지 않는다. IdP·RP 인증서의 SAN 은 이름 + IP(서버 간 호출은 IP).
TLS_OUT="$LOGS/tls"; TLS_IDP=""; TLS_RP1=""; TLS_RP2=""
tls_lines() { REPLY="MODE3_TLS_CERT=$1/zkd-demo/tls/$2.crt
MODE3_TLS_KEY=$1/zkd-demo/tls/$2.key
NODE_EXTRA_CA_CERTS=$1/zkd-demo/tls/ca.crt"; }
deploy_tls() { # $1 호스트 $2 short — 파일을 보내고 role.env 에 넣을 세 줄을 REPLY 에 남긴다
  local rh; rh=$(on "$1" 'printf %s "$HOME"') && [ -n "$rh" ] || return 1
  on "$1" 'mkdir -p -m 700 ~/zkd-demo/tls && chmod 700 ~/zkd-demo/tls' && scp -q -o BatchMode=yes -o ConnectTimeout=5 "$TLS_OUT/$2.crt" "$TLS_OUT/$2.key" "$ZKD_CA_DIR/ca.crt" "$U@$1:zkd-demo/tls/" \
    && on "$1" 'chmod 600 ~/zkd-demo/tls/*.key' || return 1
  tls_lines "$rh" "$2"
}
if [ "$WALLET_MODE" = passkey-web ]; then
  . scripts/zkd_tls_lib.sh
  { zkd_issue_cert "$ZKD_CA_DIR" "$TLS_OUT" wallet wallet.zkd.test 127.0.0.1 \
    && { [ "$ZW" = 1 ] || zkd_issue_cert "$ZKD_CA_DIR" "$TLS_OUT" idp idp.zkd.test "$IDP"; } \
    && zkd_issue_cert "$ZKD_CA_DIR" "$TLS_OUT" zkone zkone.zkd.test "$RP1" \
    && zkd_issue_cert "$ZKD_CA_DIR" "$TLS_OUT" zktwo zktwo.zkd.test "$RP2"; } >/dev/null || { echo "인증서 발급 실패 — $ZKD_CA_DIR 의 데모 CA 확인"; exit 1; }
  # zkwrapper: 지갑 서버가 발급자이기도 해서 서비스 VM 이 서버끼리 부른다 — 이 PC 의 IP 를 넣은 인증서를 따로 만든다(지갑 인증서는 그대로 이름·127.0.0.1 뿐)
  if [ "$ZW" = 1 ]; then zkd_issue_cert "$ZKD_CA_DIR" "$TLS_OUT" zkwrapper zkwrapper.zkd.test 127.0.0.1 "$HOST" >/dev/null || { echo "인증서 발급 실패(zkwrapper)"; exit 1; }; fi
  { [ "$ZW" = 1 ] || { deploy_tls "$IDP" idp && TLS_IDP="$REPLY"; }; } && deploy_tls "$RP1" zkone && TLS_RP1="$REPLY" && deploy_tls "$RP2" zktwo && TLS_RP2="$REPLY" || { echo "인증서 배포 실패(ssh·scp)"; exit 1; }
  echo "인증서 배포 ok: $([ "$ZW" = 1 ] || echo 'idp·')zkone·zktwo (VM ~/zkd-demo/tls), 지갑은 $TLS_OUT"
fi

# VM 시계(2026-11-22, 11-18 리뷰 3번): 입금·구매 본문 시각은 브라우저(이 PC) 시계, 판정은 서비스 VM 시계 ±5분이고, zkIdP·zkWrapper 토큰도 서비스 VM 시계로
# 검증한다. VM 을 일시 중지했다 재개하면(격리 망, NTP 없음) 시계가 어긋나 정상 요청이 request_replayed·bad_id_token 으로 막힌다 — 기동할 때 재서 경고만 한다.
CLOCK_VMS=("$RP1" "$RP2"); [ "$ZW" = 1 ] || CLOCK_VMS=("$IDP" "${CLOCK_VMS[@]}")
for h in "${CLOCK_VMS[@]}"; do
  _vm_t="$(on "$h" 'date +%s' 2>/dev/null)"; _here_t="$(date +%s)"
  case "$_vm_t" in ''|*[!0-9]*) echo "  경고: VM $h 의 시계를 읽지 못했다(ssh)"; continue ;; esac
  _skew=$(( _vm_t - _here_t )); [ "$_skew" -lt 0 ] && _skew=$(( -_skew ))
  [ "$_skew" -gt "${CLOCK_SKEW_WARN_SECONDS:-30}" ] && echo "  경고: VM $h 의 시계가 이 PC 와 ${_skew}초 어긋난다 — 입금·구매(±5분)·로그인 토큰(허용 60초)이 거절될 수 있다. VM 에서 sudo date -s \"@\$(date +%s)\" 처럼 맞춘다(이 PC 의 시각을 넣는다)"
done; unset _vm_t _here_t _skew CLOCK_VMS

# 2. 옛 상태 파일은 새 체인과 맞지 않으므로 .bak-시각 으로 옮긴다(지우지 않는다). IdP 키(cia_keys.json)는 그대로 둔다.
[ "$ZW" = 1 ] || on "$IDP" "cd ~/zkd-demo && for f in cia_state.json; do [ -e \$f ] && mv \$f \$f.bak-$TS && echo \"backup IdP \$f\"; done; true"
if [ "$ZW" = 1 ]; then mkdir -p -m 700 "$ZW_DIR" && { [ -e "$ZW_DIR/cia_state.json" ] && mv "$ZW_DIR/cia_state.json" "$ZW_DIR/cia_state.json.bak-$TS" && echo "backup zkWrapper cia_state.json"; true; }; fi   # 열쇠(cia_keys.json)는 그대로
for h in "$RP1" "$RP2"; do
  # mode3_rp_*_registration.json/_logins.jsonl 은 scripts/new_rp.sh --host 가 이 VM 에 만든 추가 RP 들의 등록·로그인 로그다
  # (없으면 글롭이 그대로 남지만 [ -e ] 가 걸러 조용히 건너뛴다, 2026-10-23)
  # 보관 계정의 시드(mode3_rp_custody_seed.json, 2026-11-25)는 계정 파일과 **함께** 옮긴다 — 한쪽만 남으면 지문이 맞지 않아 서비스가 뜨지 않는다.
  # 계정 파일(mode3_rp_accounts.json — 로그인 수단별 색인·KRW·시드 지문)도 옮긴다(리뷰 2026-11-19 I-2): zkIdP 의 uid 는 새로 시작하면 100001 부터 다시 매겨지므로,
  # 남겨 두면 새 사용자의 일반 OIDC 로그인(sub = uid)이 지난 실행의 다른 사람 계정에 붙는다. PPID·주소도 새 체인과 맞지 않는다.
  on "$h" "cd ~/zkd-demo && for f in mode3_rp_registration.json mode3_rp_logins.jsonl mode3_rp_accounts.json mode3_rp_*_registration.json mode3_rp_*_logins.jsonl mode3_rp_*_accounts.json mode3_rp_custody_seed.json mode3_rp_*_custody_seed.json; do [ -e \$f ] && mv \$f \$f.bak-$TS && echo \"backup $h \$f\"; done; true"
done

# 2b. Snap 모드: 이 VM 의 에이전트 상태 파일도 새 체인과 맞지 않는다 — .bak-시각 으로 옮긴다(MetaMask 안의 Snap 상태는 못 지운다 — 지갑 페이지 'Snap 초기화').
if [ "$AGENT_MODE" = 1 ]; then for f in mode3_wallet_state.json mode3_wallet_rcl.json; do [ -e "$f" ] && mv "$f" "$f.bak-$TS" && echo "backup $f"; done; fi
# 2c. (2026-11-11 사용자 요청) 속성 커밋먼트 도구(localhost:5100/attr.html)의 기록은 브라우저 저장소라 여기서 지울 수 없다 — 리셋 시각을 정적 파일로 남기면
#     도구·스냅 팝업이 그 값이 바뀐 것을 보고 이전 데모의 기록(uid·salt)을 비운다. mode3/attr/dist 는 ignore 된 번들 폴더(에이전트가 /attr/ 로 서빙).
# 속성 도구는 이 파일의 walletKind 로 화면 모드를 다시 정한다 — zkwrapper 는 이 스크립트 안에서 WALLET_MODE=passkey-web 이라 따로 적는다(2026-11-25, 전에는 래퍼에서도 passkey-web 문구가 나왔다).
if [ "$AGENT_MODE" = 1 ] || [ "$WALLET_MODE" = passkey-web ]; then mkdir -p mode3/attr/dist && printf '{"epoch":"%s","walletKind":"%s"}\n' "$TS" "$([ "$ZW" = 1 ] && echo zkwrapper || echo "$WALLET_MODE")" > mode3/attr/dist/reset.json && echo "attr 도구 리셋 표시: $TS"; fi
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

# 3b. Blockscout 초기화(2026-11-17 사용자 요청): 로컬 Blockscout(.local/blockscout, :4000)는 응용 체인(:$APP_PORT)을 색인한다. 체인을 새로 만들면
#     DB 에 옛 체인의 블록이 남아 새 블록 번호(≤ 옛 최고 높이)를 이미 색인한 것으로 보고 갱신하지 않는다 — 색인 볼륨을 지우고 다시 띄운다.
#     compose 파일이 없거나 docker 가 없으면 건너뛴다. BLOCKSCOUT_RESET=0 이면 끈다. 체인에서 다시 만들어지는 색인뿐이라 데모 상태 파일과 무관하다.
#     2026-11-18: compose 프로젝트 이름을 준다($BS_PROJECT, 기본 zkid-blockscout) — 이름 없이 부르면 디렉터리 이름(blockscout)의 다른 스택에 걸려
#     화면에 보이는 스택은 그대로 남고, 중복 스택의 proxy 가 :4000 충돌로 실패했다.
BS_DIR=".local/blockscout"; BS_RESET_OK=0; BS_RCL_OK=0
# 탐색기 주소(2026-11-18): 사용자 페이지(web·passkey-web)의 증명 기록이 거래 링크를 여기에 건다. Blockscout 가 없으면 비어 있다(BLOCKSCOUT_URL 로 바꾼다).
BS_EXPLORER=$([ -f "$BS_DIR/compose.yml" ] && echo "${BLOCKSCOUT_URL:-http://127.0.0.1:4000}")
if [ "${BLOCKSCOUT_RESET:-1}" != 0 ] && [ -f "$BS_DIR/compose.yml" ] && command -v docker >/dev/null 2>&1; then
  if (cd "$BS_DIR" && docker compose -p "$BS_PROJECT" down -v >"$LOGS/blockscout_reset.log" 2>&1 && docker compose -p "$BS_PROJECT" up -d >>"$LOGS/blockscout_reset.log" 2>&1); then
    BS_RESET_OK=1; echo "Blockscout 초기화($BS_PROJECT): 색인을 비우고 다시 띄웠다(http://127.0.0.1:4000 — 새 체인을 0번부터 색인한다)"
  else
    echo "WARN Blockscout 초기화 실패 — $LOGS/blockscout_reset.log (데모는 계속 진행)"
  fi
fi
# 3b-2. 폐기(RCL) 체인(:$REV_PORT)의 Blockscout(http://127.0.0.1:4001, 2026-11-25) — 응용 체인 것과 볼륨·네트워크가 따로인 두 번째 스택이다. 체인을 새로 만들었으니 색인도 비운다.
#       BLOCKSCOUT_RCL=0 이면 건드리지 않는다. 실패해도 데모는 계속한다.
if [ "${BLOCKSCOUT_RESET:-1}" != 0 ] && [ "${BLOCKSCOUT_RCL:-1}" != 0 ] && [ -f "$BS_DIR/compose.yml" ]; then
  if bash scripts/blockscout_rcl.sh reset > "$LOGS/blockscout_rcl_reset.log" 2>&1; then BS_RCL_OK=1; echo "Blockscout(RCL) 초기화: 폐기 체인 색인을 비우고 다시 띄웠다(http://127.0.0.1:4001)"; else echo "WARN Blockscout(RCL) 초기화 실패 — $LOGS/blockscout_rcl_reset.log (데모는 계속 진행)"; fi
fi
# 3c. 컨트랙트 자동 검증(2026-11-18): 감시자 하나가 응용 체인을 0번 블록부터 따라가며 올라오는 컨트랙트(거울·검증기·팩토리·AttrGate·계정마다의 지갑)를
#     Blockscout 에 소스 검증으로 올린다. 서비스(VM)·에이전트가 실행 중에 배포하는 것까지 체인에서 잡는다. BLOCKSCOUT_VERIFY=0 이면 띄우지 않는다.
#     Blockscout 가 없으면(compose·docker 없음, 또는 초기화를 건너뛰었는데 :4000 응답 없음) 띄우지 않는다. 데모 기동은 이 감시자를 기다리지 않는다.
if [ "${BLOCKSCOUT_VERIFY:-1}" != 0 ] && [ -f "$BS_DIR/compose.yml" ] && command -v docker >/dev/null 2>&1 \
   && { [ "$BS_RESET_OK" = 1 ] || curl -s -m 3 -o /dev/null http://127.0.0.1:4000/api/v2/stats; }; then
  BS_RPC="http://127.0.0.1:$APP_PORT" setsid nohup node scripts/blockscout_verify_watch.mjs > "$LOGS/blockscout_verify.log" 2>&1 < /dev/null &
  echo $! > "$BS_VERIFY_PID"
  echo "Blockscout 자동 검증 감시자 up (pid $(cat "$BS_VERIFY_PID")) — $LOGS/blockscout_verify.log"
fi
# 3c-2. 폐기 체인의 감시자(2026-11-25) — 캐노니컬 로그(Mode3Log)를 :4001 에 소스 검증으로 올린다. 켜고 끄는 조건은 3b-2·3c 와 같다.
if [ "${BLOCKSCOUT_VERIFY:-1}" != 0 ] && [ "${BLOCKSCOUT_RCL:-1}" != 0 ] && [ -f "$BS_DIR/compose.yml" ] && command -v docker >/dev/null 2>&1 \
   && { [ "$BS_RCL_OK" = 1 ] || curl -s -m 3 -o /dev/null http://127.0.0.1:4001/api/v2/stats; }; then
  BS_URL="http://127.0.0.1:4001" BS_RPC="http://127.0.0.1:$REV_PORT" setsid nohup node scripts/blockscout_verify_watch.mjs > "$LOGS/blockscout_verify_rcl.log" 2>&1 < /dev/null &
  echo $! > "$BS_VERIFY_RCL_PID"
  echo "Blockscout(RCL) 자동 검증 감시자 up (pid $(cat "$BS_VERIFY_RCL_PID")) — $LOGS/blockscout_verify_rcl.log"
fi

# 4. IdP 주소: 임시 상태 파일로 IdP 를 한 번 띄워 /cia/public_keys 의 ethAddress 를 읽는다(배포 스크립트 안내대로). 키는 idp VM 안에만 생긴다.
if [ "$ZW" = 1 ]; then
  # zkwrapper: 열쇠는 이 PC 의 $ZW_DIR 에 생긴다 — 같은 열쇠 파일로 보통 방식의 cia.js 를 127.0.0.1 의 빈 포트에 잠깐 띄워 주소만 읽고 내린다(.env 는 읽지 않는다)
  : > "$LOGS/empty.env"; KP_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
  DOTENV_CONFIG_PATH="$LOGS/empty.env" CIA_WRAPPER= CIA_USER_APP= CIA_PORT=$KP_PORT MODE3_BIND_HOST=127.0.0.1 CIA_STATE_FILE="$LOGS/cia_keyprobe_state.json" CIA_KEYS_FILE="$ZW_DIR/cia_keys.json" \
    CIA_RPC_URL="http://127.0.0.1:$REV_PORT" MODE3_TLS_CERT= MODE3_TLS_KEY= setsid nohup node cia.js > "$LOGS/cia_keyprobe.log" 2>&1 < /dev/null &
  KP_PID=$!
  ADDR=$(for i in $(seq 1 30); do r=$(curl -s -m 2 "http://127.0.0.1:$KP_PORT/cia/public_keys") && [ -n "$r" ] && { echo "$r"; break; }; sleep 1; done | python3 -c "import sys,json;print(json.load(sys.stdin)['ethAddress'])" 2>/dev/null)
  kill "$KP_PID" 2>/dev/null; sleep 1; rm -f "$LOGS/cia_keyprobe_state.json"
  [ -n "$ADDR" ] || { echo "zkWrapper 주소를 못 읽었다 — $LOGS/cia_keyprobe.log"; exit 1; }
else
on "$IDP" "cd ~/zkd-demo && { CIA_STATE_FILE=/tmp/cia_keyprobe_state.json CIA_RPC_URL=http://$HOST:$REV_PORT setsid nohup \$HOME/zkd-demo/bin/node cia.js > logs/cia_keyprobe.log 2>&1 < /dev/null & }"
ADDR=$(on "$IDP" "for i in \$(seq 1 30); do r=\$(curl -s -m 2 http://127.0.0.1:$IDP_PORT/cia/public_keys) && [ -n \"\$r\" ] && { echo \"\$r\"; break; }; sleep 1; done" | python3 -c "import sys,json;print(json.load(sys.stdin)['ethAddress'])" 2>/dev/null)
on "$IDP" "pkill -f '[z]kd-demo/bin/node cia.js'; sleep 1; rm -f /tmp/cia_keyprobe_state.json"
[ -n "$ADDR" ] || { echo "IdP 주소를 못 읽었다 — idp 의 ~/zkd-demo/logs/cia_keyprobe.log"; exit 1; }
fi
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

# 5b. 추적 기록 등록부(2026-11-26 스펙 ppid-account-trace) — zkwrapper 방식에서만. 응용 체인에 TraceVerifier·TraceRegistry 를 올리고 감사자 프로세스를 띄운다
#     (데모 — 한 프로세스가 감사자 셋을 흉내 낸다). TRACE=0 이면 끈다. 회로 산출물(build/mode3/pi_trace_*)이나 컴파일 산출물이 없으면 건너뛴다 — 끈 것과 같고 로그인은 지금처럼 된다.
#     감사자 키(조각)는 .local/auditors 에 남는다(값은 출력하지 않는다). 체인을 새로 만들었으니 등록부는 매번 새로 올린다(키는 그대로).
TRACE_REG=""; AUDITOR_TOKEN=""
if [ "$ZW" = 1 ] && [ "${TRACE:-1}" != 0 ]; then
  if [ -f build/mode3/pi_trace_final.zkey ] && [ -f artifacts/contracts/TraceRegistry.sol/TraceRegistry.json ]; then
    RPC="http://127.0.0.1:$APP_PORT" MODE3_AUDITOR_DIR="${AUDITOR_DIR:-.local/auditors}" node scripts/mode3_trace_setup.mjs > "$LOGS/trace_setup.log" 2>&1 || true
    TRACE_REG=$(grep -oE "MODE3_TRACE_REGISTRY=0x[0-9a-fA-F]+" "$LOGS/trace_setup.log" | head -1 | cut -d= -f2)
    if [ -n "$TRACE_REG" ]; then
      # 감사자와 조합자(zkWrapper)가 나눠 갖는 토큰 — 띄울 때마다 새로 뽑아 두 프로세스의 환경으로만 넘긴다(출력·파일 없음)
      AUDITOR_TOKEN=$(node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))")
      MODE3_AUDITOR_DIR="${AUDITOR_DIR:-.local/auditors}" MODE3_AUDITOR_RPC="http://127.0.0.1:$APP_PORT" MODE3_TRACE_REGISTRY="$TRACE_REG" MODE3_AUDITOR_PORT="${AUDITOR_PORT:-5300}" MODE3_AUDITOR_TOKEN="$AUDITOR_TOKEN" \
        setsid nohup node mode3_auditors.js > "$LOGS/auditors.log" 2>&1 < /dev/null &
      echo "추적 기록 등록부 $TRACE_REG · 감사자 프로세스 up(:${AUDITOR_PORT:-5300}) — $LOGS/auditors.log"
    else echo "WARN 추적 기록 등록부 배포 실패 — $LOGS/trace_setup.log (추적 기록 없이 계속한다)"; fi
  else echo "추적 기록: 산출물이 없어 건너뛴다(bash scripts/build_mode3_circuit.sh pi_trace && npx hardhat compile)"; fi
fi

# 6. 역할별 설정 파일(각 VM 에 자기 것만, 권한 600)과 기동
WALLET_KIND_OUT="$WALLET_MODE"; [ "$ZW" = 1 ] && WALLET_KIND_OUT=zkwrapper   # 서비스 화면이 보는 지갑 종류 — zkwrapper 면 지갑 서버를 부르지 않는다(스펙 §5)
COMMON="CIA_LOG_ADDRESS=$LOGADDR
MODE3_MIRROR_ADDRESS=$MIRROR
CIA_MIRRORS=$MIRRORS
MODE3_WALLET_AGENT_ORIGIN=$WALLET_ORIGIN
MODE3_WALLET_KIND=$WALLET_KIND_OUT
CIA_PLAIN_OIDC=$PLAIN_OIDC
MODE3_RP_ZKOIDC=$PLAIN_OIDC
MODE3_VERIFIER_ADDRESS=
MODE3_RP_FACTORY_ADDRESS=
MODE3_BIND_HOST=0.0.0.0
MODE3_CIA_BROWSER_URL=$IDP_UI
MODE3_TRACE_REGISTRY=$TRACE_REG"
put_env() { on "$1" "umask 077 && cat > ~/zkd-demo/role.env && chmod 600 ~/zkd-demo/role.env"; }
# OIDC 래퍼 클라이언트 ID(2026-10-26 Snap OIDC 래퍼 §3) — 값은 어디에도 출력하지 않는다(진행 줄은 on/off 만).
oidc_client_id() { [ -n "${MODE3_OIDC_CLIENT_ID:-}" ] && { printf '%s' "$MODE3_OIDC_CLIENT_ID"; return; }; [ -f "$1" ] && sed -n 's/^GOOGLE_CLIENT_ID=//p' "$1" | head -n1 | tr -d '\r"'"'"; }
OIDC_LINE=""
if [ "${OIDC:-1}" != 0 ]; then OIDC_ID="$(oidc_client_id .env)"; [ -n "$OIDC_ID" ] && OIDC_LINE="MODE3_OIDC_CLIENT_ID=$OIDC_ID"; unset OIDC_ID; fi
[ "$ZW" = 1 ] || echo "  OIDC(Google): $([ -n "$OIDC_LINE" ] && echo on || echo off)"
# zkwrapper(2026-11-21 실제 기동 셀프 피드백): IdP 가 없다 — 공유 ID 는 전용 ID(RP1·RP2_GOOGLE_CLIENT_ID)가 없는 서비스로만 간다. 그 이름을 댄다.
if [ "$ZW" = 1 ]; then
  _shared_to=""; [ -z "${MODE3_OIDC_CLIENT_ID:-}" ] && [ -n "$OIDC_LINE" ] && { [ -n "${RP1_GOOGLE_CLIENT_ID:-}" ] || _shared_to="zkONE"; [ -n "${RP2_GOOGLE_CLIENT_ID:-}" ] || _shared_to="${_shared_to:+$_shared_to·}zkTWO"; }
  [ -n "$_shared_to" ] && echo "  경고: .env 의 GOOGLE_CLIENT_ID(Mode 1 공유 클라이언트 ID)를 서비스($_shared_to)에 넘긴다 — 같은 ID 의 다른 앱 토큰을 받을 수 있다(서비스 전용 ID 는 RP1_GOOGLE_CLIENT_ID·RP2_GOOGLE_CLIENT_ID)"; unset _shared_to
elif [ -z "${MODE3_OIDC_CLIENT_ID:-}" ] && [ -n "$OIDC_LINE" ]; then echo "  경고: .env 의 GOOGLE_CLIENT_ID(Mode 1 공유 클라이언트 ID)를 IdP 에 넘긴다 — 같은 ID 의 다른 앱 토큰을 받을 수 있다(선행 스펙 §5)"; fi
# RP 소셜(2026-11-10) — 값은 출력하지 않는다(on/off 만). Google 은 IdP 래퍼와 같은 클라이언트 ID 를 RP 에도 준다. 네이버 ID·Secret 은 RP role.env 에만(IdP 에는 주지 않는다).
env_or_dotenv() { [ -n "${!1:-}" ] && { printf '%s' "${!1}"; return; }; [ -f .env ] && sed -n "s/^$1=//p" .env | head -n1 | tr -d '\r"'"'"; }
RP_GOOGLE_LINE=""; [ -n "$OIDC_LINE" ] && RP_GOOGLE_LINE="MODE3_RP_GOOGLE_CLIENT_ID=${OIDC_LINE#MODE3_OIDC_CLIENT_ID=}"
# 2026-11-19(데모 시나리오 3·4 — 실제 Google OIDC): passkey-web 에서는 서비스가 Google 에 **리디렉션식**으로 다녀온다. Google 은 공개 도메인이나 localhost 만 돌아올 주소로 받으므로
# (*.zkd.test 불가) 지갑 정적 서버의 https://127.0.0.1:<포트>/google-relay 를 쓴다 — Google 콘솔의 "승인된 리디렉션 URI" 에 이 주소가 있어야 한다. 서비스마다 클라이언트 ID 를
# 따로 주면(RP1_GOOGLE_CLIENT_ID·RP2_GOOGLE_CLIENT_ID) 토큰의 aud(= rid)가 서비스마다 달라진다. 없으면 위의 공유 ID. 값은 출력하지 않는다.
GOOGLE_RELAY=""; [ "$WALLET_MODE" = passkey-web ] && GOOGLE_RELAY="https://127.0.0.1:$USER_PORT/google-relay"
rp_google_lines() { local id="${1:-${RP_GOOGLE_LINE#MODE3_RP_GOOGLE_CLIENT_ID=}}"; [ -n "$id" ] || return 0; printf '%s\n' "MODE3_RP_GOOGLE_CLIENT_ID=$id"; [ -n "$GOOGLE_RELAY" ] && printf '%s\n' "MODE3_RP_GOOGLE_REDIRECT_URI=$GOOGLE_RELAY"; return 0; }
NAVER_ID="$(env_or_dotenv MODE3_NAVER_CLIENT_ID)"; NAVER_SECRET="$(env_or_dotenv MODE3_NAVER_CLIENT_SECRET)"
rp_naver_lines() { [ -n "$NAVER_ID" ] && [ -n "$NAVER_SECRET" ] && printf '%s\n' "MODE3_RP_NAVER_CLIENT_ID=$NAVER_ID" "MODE3_RP_NAVER_CLIENT_SECRET=$NAVER_SECRET" "MODE3_RP_NAVER_REDIRECT_URI=$1/api/rp/naver/callback"; return 0; }
echo "  RP 소셜: Google $([ -n "$RP_GOOGLE_LINE${RP1_GOOGLE_CLIENT_ID:-}${RP2_GOOGLE_CLIENT_ID:-}" ] && echo on || echo off)${GOOGLE_RELAY:+(리디렉션식 — Google 콘솔의 승인된 리디렉션 URI: $GOOGLE_RELAY)} · 네이버 $([ -n "$NAVER_ID" ] && [ -n "$NAVER_SECRET" ] && echo on || echo off)   브라우저용 주소: IdP $IDP_UI · zkONE $RP1_UI · zkTWO $RP2_UI"
# 리뷰 2026-11-19(OIDC I-1·M-9): 두 서비스가 같은 Google 클라이언트 ID 를 쓰면 토큰의 aud(= rid)가 같게 찍혀 "Google 은 어느 서비스인지 안다" 를 화면으로 보일 수 없다. 값은 출력하지 않는다.
# 2026-11-20(스펙 passkey-google-signup G8·G9): zkIdP 의 "패스키로 로그인" 이 미등록 브라우저에서 Google 로 확인한 이메일로 계정을 만든다 — 지갑 창이 같은 중계 주소로 Google 에 다녀온다.
# zkIdP 의 Google 클라이언트(OIDC_LINE)에도 Google 콘솔의 "승인된 리디렉션 URI" 로 이 주소가 있어야 한다. passkey-web 이고 Google 이 켜져 있을 때만 넘긴다.
IDP_SIGNUP_LINE=""; [ -n "$GOOGLE_RELAY" ] && [ -n "$OIDC_LINE" ] && IDP_SIGNUP_LINE="MODE3_OIDC_REDIRECT_URI=$GOOGLE_RELAY"
# C2(2026-11-22, zkwrapper 스펙 §10 과 같은 약점): zkIdP 가 서비스와 같은 Google ID 로 패스키 가입을 열면, 악의적 서비스가 자기가 고른 nonce 로 피해자의 토큰을 받아
# 피해자 Google 계정의 zkIdP 계정을 먼저 만들 수 있다. 서비스가 받는 ID 목록을 zkIdP 에 넘긴다(cia.js 가 그 ID 면 가입을 닫는다). 값은 출력하지 않는다.
IDP_DENY_LINE=""; _sig_off=""
if [ "$ZW" != 1 ] && [ -n "$IDP_SIGNUP_LINE" ]; then
  _rp_shared="${RP_GOOGLE_LINE#MODE3_RP_GOOGLE_CLIENT_ID=}"
  _deny="$(printf '%s\n' "${RP1_GOOGLE_CLIENT_ID:-$_rp_shared}" "${RP2_GOOGLE_CLIENT_ID:-$_rp_shared}" | awk 'NF' | sort -u | paste -sd, -)"
  [ -n "$_deny" ] && IDP_DENY_LINE="MODE3_RP_GOOGLE_CLIENT_ID_DENY=$_deny"
  printf '%s\n' "${_deny//,/$'\n'}" | grep -qxF -- "${OIDC_LINE#MODE3_OIDC_CLIENT_ID=}" && _sig_off=" (서비스와 같은 Google 클라이언트 ID 라 닫는다 — 패스키 가입에는 zkIdP 전용 ID 가 필요하다: MODE3_OIDC_CLIENT_ID 와 RP1_GOOGLE_CLIENT_ID·RP2_GOOGLE_CLIENT_ID 를 서로 다르게. 아이디·비밀번호 가입은 그대로)"
  unset _rp_shared _deny
fi
[ "$ZW" = 1 ] || echo "  zkIdP 패스키 가입(Google 이메일): $([ -n "$IDP_SIGNUP_LINE" ] && [ -z "$_sig_off" ] && echo on || echo "off$_sig_off")"
unset _sig_off
if [ -n "$GOOGLE_RELAY" ]; then
  _g1="${RP1_GOOGLE_CLIENT_ID:-${RP_GOOGLE_LINE#MODE3_RP_GOOGLE_CLIENT_ID=}}"; _g2="${RP2_GOOGLE_CLIENT_ID:-${RP_GOOGLE_LINE#MODE3_RP_GOOGLE_CLIENT_ID=}}"
  if [ -n "$_g1" ] && [ "$_g1" = "$_g2" ]; then echo "  경고: zkONE·zkTWO 가 같은 Google 클라이언트 ID 를 쓴다 — 두 서비스의 ID 토큰 aud(= rid)가 같게 보인다. 서비스마다 다른 ID 를 주려면 RP1_GOOGLE_CLIENT_ID·RP2_GOOGLE_CLIENT_ID"; fi
  unset _g1 _g2
fi
[ "$ZW" = 1 ] || printf '%s\n' "$COMMON" "CIA_PORT=$IDP_PORT" "CIA_RPC_URL=http://$HOST:$REV_PORT" "CIA_CHAIN_RPCS=$APP_CHAIN=http://$HOST:$APP_PORT" "CIA_ADMIN_SECRET=$ADMIN" "CIA_ADMIN_OPEN=${ADMIN_OPEN:-0}" "CIA_PUBLIC_URL=$SCHEME://$IDP:$IDP_PORT" "CIA_ISSUE_AUTH=${ISSUE_AUTH:-$([ "$AGENT_MODE" = 1 ] && echo code || echo key)}" "CIA_REVOKE_PUBLISH_AFTER_BLOCKS=${REVOKE_PUBLISH_AFTER:-3}" ${OIDC_LINE:+"$OIDC_LINE"} ${IDP_SIGNUP_LINE:+"$IDP_SIGNUP_LINE"} ${IDP_DENY_LINE:+"$IDP_DENY_LINE"} ${TLS_IDP:+"$TLS_IDP"} | put_env "$IDP"   # zkwrapper 에는 IdP VM 이 없다
{ printf '%s\n' "$COMMON" "MODE3_RP_PORT=$RP1_PORT" "MODE3_RP_NAME=zkONE" "MODE3_RP_PUBLIC_ORIGIN=$RP1_UI" "MODE3_CIA_URL=$CIA_SRV" \
  "CIA_RPC_URL=http://$HOST:$APP_PORT" "MODE3_RELAYER_INDEX=0" "MODE3_EXPLORER_URL=$BS_EXPLORER" ${TLS_RP1:+"$TLS_RP1"}; rp_google_lines "${RP1_GOOGLE_CLIENT_ID:-}"; rp_naver_lines "$RP1_UI"; } | put_env "$RP1"
{ printf '%s\n' "$COMMON" "MODE3_RP_PORT=$RP2_PORT" "MODE3_RP_NAME=zkTWO" "MODE3_RP_PUBLIC_ORIGIN=$RP2_UI" "MODE3_CIA_URL=$CIA_SRV" \
  "CIA_RPC_URL=http://$HOST:$APP_PORT" "MODE3_RELAYER_INDEX=1" "MODE3_EXPLORER_URL=$BS_EXPLORER" "MODE3_ALLOWED_COUNTRIES=410,392" "MODE3_MIN_AGE=19" "MODE3_REQUIRE_DISCLOSURE=1" ${TLS_RP2:+"$TLS_RP2"}; rp_google_lines "${RP2_GOOGLE_CLIENT_ID:-}"; rp_naver_lines "$RP2_UI"; } | put_env "$RP2"
unset NAVER_ID NAVER_SECRET
start_remote() { # $1 호스트 $2 스크립트 $3 포트
  on "$1" "cd ~/zkd-demo && set -a && . ./role.env && set +a && { setsid nohup \$HOME/zkd-demo/bin/node $2 > logs/${2%.js}.log 2>&1 < /dev/null & }"
  for i in $(seq 1 40); do curl -s -m 2 "${CACERT[@]}" -o /dev/null "$SCHEME://$1:$3/mode3/health" && { echo "$2 up at $SCHEME://$1:$3"; return 0; }; sleep 1; done
  echo "$2 at $1:$3 failed — $1 의 ~/zkd-demo/logs/${2%.js}.log"; exit 1
}
[ "$ZW" = 1 ] || start_remote "$IDP" cia.js $IDP_PORT   # zkwrapper: 발급자는 아래 지갑 자리에서 뜬다
if [ "$SPLIT_IDP_TUNNEL" != 0 ]; then
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o ExitOnForwardFailure=yes -f -N $TUNNEL_SPEC "$U@$IDP" && curl -s -m 3 -o /dev/null "$IDP_UI/mode3/health" \
    && echo "IdP 터널 up: $IDP_UI → $IDP:$IDP_PORT" || { echo "IdP 터널 실패($TUNNEL_SPEC $U@$IDP)"; exit 1; }
fi
: > "$LOGS/empty.env"
if [ "$WALLET_MODE" = "snap" ]; then
  # Snap 모드(2026-10-22): 에이전트는 증명·동기화만, 비밀은 MetaMask 의 Snap 안. 릴레이어 계정은 RP 둘(0·1)과 겹치지 않게 2. .env 는 읽지 않는다(DOTENV_CONFIG_PATH).
  DOTENV_CONFIG_PATH="$LOGS/empty.env" MODE3_WALLET_SECRETS=snap MODE3_SNAP_ID="local:http://localhost:$SNAP_PORT" MODE3_WALLET_PORT=$USER_PORT MODE3_WALLET_PUBLIC_ORIGIN="$WALLET_ORIGIN" \
    MODE3_DEMO_RACE="${DEMO_RACE:-1}" MODE3_CIA_URL="$IDP_UI" MODE3_RP_ORIGIN="$RP1_UI,$RP2_UI" MODE3_RELAYER_INDEX=2 MODE3_HEIGHT_GRID="${HEIGHT_GRID:-5}" MODE3_TTL_BLOCKS="${TTL_BLOCKS:-5}" \
    CIA_RPC_URL="http://127.0.0.1:$APP_PORT" MODE3_REV_CHAIN_RPC="http://127.0.0.1:$REV_PORT" CIA_LOG_ADDRESS="$LOGADDR" MODE3_MIRROR_ADDRESS="$MIRROR" \
    setsid nohup node mode3_wallet_agent.js > "$LOGS/wallet_agent.log" 2>&1 < /dev/null &
  (cd snap-mode3 && setsid nohup npm run serve > "$LOGS/snap_serve.log" 2>&1 < /dev/null &)
  timeout 40 bash -c "until ss -ltn | grep -q ':$SNAP_PORT '; do sleep 1; done" && echo "snap serve :$SNAP_PORT up" || { echo "snap serve failed — $LOGS/snap_serve.log"; exit 1; }
elif [ "$WALLET_MODE" = "passkey" ]; then
  # 패스키 모드(2026-11-17): snap 과 같은 에이전트 설정에서 스냅만 뺀다 — salt 는 zk 스냅 화면이 패스키 PRF 로 그때그때 만든다. 지갑 오리진은 localhost 여야 뜬다.
  DOTENV_CONFIG_PATH="$LOGS/empty.env" MODE3_WALLET_SECRETS=passkey MODE3_WALLET_PORT=$USER_PORT MODE3_WALLET_PUBLIC_ORIGIN="$WALLET_ORIGIN" \
    MODE3_DEMO_RACE="${DEMO_RACE:-1}" MODE3_CIA_URL="$IDP_UI" MODE3_RP_ORIGIN="$RP1_UI,$RP2_UI" MODE3_RELAYER_INDEX=2 MODE3_HEIGHT_GRID="${HEIGHT_GRID:-5}" MODE3_TTL_BLOCKS="${TTL_BLOCKS:-5}" \
    CIA_RPC_URL="http://127.0.0.1:$APP_PORT" MODE3_REV_CHAIN_RPC="http://127.0.0.1:$REV_PORT" CIA_LOG_ADDRESS="$LOGADDR" MODE3_MIRROR_ADDRESS="$MIRROR" \
    setsid nohup node mode3_wallet_agent.js > "$LOGS/wallet_agent.log" 2>&1 < /dev/null &
elif [ "$WALLET_MODE" = passkey-web ] && [ "$ZW" = 1 ]; then
  # zkwrapper(2026-11-20): 지갑 화면 + 발급(Google 토큰 → 세션 토큰) 한 서버. 브라우저는 체인 노드를 직접 부른다(이 서버를 거치지 않는다 — 스펙 §5). 서비스 VM 이 서버끼리 부르므로 0.0.0.0.
  DOTENV_CONFIG_PATH="$LOGS/empty.env" CIA_LOG_ADDRESS="$LOGADDR" MODE3_MIRROR_ADDRESS="$MIRROR" CIA_MIRRORS="$MIRRORS" CIA_RPC_URL="http://127.0.0.1:$REV_PORT" CIA_CHAIN_RPCS="$APP_CHAIN=http://127.0.0.1:$APP_PORT" \
    CIA_ADMIN_SECRET="$ADMIN" CIA_ADMIN_OPEN="${ADMIN_OPEN:-0}" CIA_STATE_FILE="$ZW_DIR/cia_state.json" CIA_KEYS_FILE="$ZW_DIR/cia_keys.json" CIA_PUBLIC_URL="$WALLET_ORIGIN" MODE3_WALLET_AGENT_ORIGIN="$WALLET_ORIGIN" \
    MODE3_OIDC_CLIENT_ID="$ZKWRAPPER_GOOGLE_CLIENT_ID" MODE3_OIDC_REDIRECT_URI="$GOOGLE_RELAY" MODE3_RP_GOOGLE_CLIENT_ID_DENY="$ZW_DENY" \
    MODE3_CHAIN_RPC_BROWSER="http://127.0.0.1:$APP_PORT" MODE3_REV_RPC_BROWSER="http://127.0.0.1:$REV_PORT" MODE3_DEMO_GENERATION="$(date +%s)" MODE3_EXPLORER_URL="$BS_EXPLORER" \
    MODE3_TTL_BLOCKS="${TTL_BLOCKS:-5}" MODE3_HEIGHT_GRID="${HEIGHT_GRID:-5}" MODE3_ZKWRAPPER_PORT=$USER_PORT MODE3_BIND_HOST=0.0.0.0 CIA_REVOKE_PUBLISH_AFTER_BLOCKS="${REVOKE_PUBLISH_AFTER:-3}" \
    MODE3_TLS_CERT="$TLS_OUT/zkwrapper.crt" MODE3_TLS_KEY="$TLS_OUT/zkwrapper.key" NODE_EXTRA_CA_CERTS="$ZKD_CA_DIR/ca.crt" \
    MODE3_TRACE_REGISTRY="$TRACE_REG" MODE3_AUDITOR_URL="http://127.0.0.1:${AUDITOR_PORT:-5300}" MODE3_AUDITOR_TOKEN="${AUDITOR_TOKEN:-}" \
    setsid nohup node mode3_zkwrapper.js > "$LOGS/zkwrapper.log" 2>&1 < /dev/null &
elif [ "$WALLET_MODE" = passkey-web ]; then
  # passkey-web(2026-11-17): web 분기와 같은 정적 서버를 https 로 — 인증서는 위에서 만든 지갑 것, IdP·RP 인증서를 검증할 데모 CA 를 NODE_EXTRA_CA_CERTS 로 준다.
  DOTENV_CONFIG_PATH="$LOGS/empty.env" MODE3_PK_CIA_X="" MODE3_PK_CIA_Y="" MODE3_HEIGHT_GRID="${HEIGHT_GRID:-5}" MODE3_DEMO_GENERATION="$(date +%s)" MODE3_WALLET_PORT=$USER_PORT MODE3_WALLET_PUBLIC_ORIGIN="$WALLET_ORIGIN" \
    MODE3_WALLET_SECRETS=passkey-web MODE3_EXPLORER_URL="$BS_EXPLORER" MODE3_TTL_BLOCKS="${TTL_BLOCKS:-5}" MODE3_TLS_CERT="$TLS_OUT/wallet.crt" MODE3_TLS_KEY="$TLS_OUT/wallet.key" NODE_EXTRA_CA_CERTS="$ZKD_CA_DIR/ca.crt" \
    MODE3_CIA_URL="$IDP_UI" MODE3_RP_ORIGIN="$RP1_UI,$RP2_UI" \
    CIA_RPC_URL="http://127.0.0.1:$APP_PORT" MODE3_REV_CHAIN_RPC="http://127.0.0.1:$REV_PORT" CIA_LOG_ADDRESS="$LOGADDR" MODE3_MIRROR_ADDRESS="$MIRROR" \
    setsid nohup node mode3_user_static.js > "$LOGS/user_static.log" 2>&1 < /dev/null &
else
DOTENV_CONFIG_PATH="$LOGS/empty.env" MODE3_PK_CIA_X="" MODE3_PK_CIA_Y="" MODE3_HEIGHT_GRID="${HEIGHT_GRID:-5}" MODE3_DEMO_GENERATION="$(date +%s)" MODE3_WALLET_PORT=$USER_PORT MODE3_WALLET_PUBLIC_ORIGIN="$WALLET_ORIGIN" \
  MODE3_CIA_URL="$IDP_UI" MODE3_RP_ORIGIN="$RP1_UI,$RP2_UI" MODE3_EXPLORER_URL="$BS_EXPLORER" \
  CIA_RPC_URL="http://127.0.0.1:$APP_PORT" MODE3_REV_CHAIN_RPC="http://127.0.0.1:$REV_PORT" CIA_LOG_ADDRESS="$LOGADDR" MODE3_MIRROR_ADDRESS="$MIRROR" \
  setsid nohup node mode3_user_static.js > "$LOGS/user_static.log" 2>&1 < /dev/null &
fi
timeout 30 bash -c "until ss -ltn | grep -q ':$USER_PORT '; do sleep 1; done" && echo "지갑($WALLET_MODE) up at $WALLET_ORIGIN" || { echo "지갑($WALLET_MODE) failed — $LOGS/$([ "$AGENT_MODE" = 1 ] && echo wallet_agent || { [ "$ZW" = 1 ] && echo zkwrapper || echo user_static; }).log"; exit 1; }
start_remote "$RP1" mode3_rp.js $RP1_PORT
start_remote "$RP2" mode3_rp.js $RP2_PORT
if [ "$SPLIT_RP_TUNNEL" != 0 ]; then
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o ExitOnForwardFailure=yes -f -N $RP1_TUNNEL "$U@$RP1" && curl -s -m 3 -o /dev/null "$RP1_UI/mode3/health" \
    && echo "RP 터널 up: $RP1_UI → $RP1:$RP1_PORT" || { echo "RP 터널 실패($RP1_TUNNEL $U@$RP1)"; exit 1; }
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o ExitOnForwardFailure=yes -f -N $RP2_TUNNEL "$U@$RP2" && curl -s -m 3 -o /dev/null "$RP2_UI/mode3/health" \
    && echo "RP 터널 up: $RP2_UI → $RP2:$RP2_PORT" || { echo "RP 터널 실패($RP2_TUNNEL $U@$RP2)"; exit 1; }
fi

IDP_PAGE="$SCHEME://$IDP:$IDP_PORT"; [ "$WALLET_MODE" = passkey-web ] && IDP_PAGE="$IDP_UI"   # zkwrapper 면 IDP_UI = 지갑 오리진   # 사람이 여는 주소 — passkey-web 은 이름(IP 로 열면 패스키가 안 된다)
# 7. RP 등록 대기(승인은 기본 수동)
HDR="X-CIA-Admin-Secret: $ADMIN"
rps_json() { curl -s -m 5 "${CACERT[@]}" -H "$HDR" "$CIA_SRV/cia/rps"; }
active() { curl -s -m 5 "${CACERT[@]}" "$SCHEME://$1/mode3/health" | python3 -c "import sys,json;print(json.load(sys.stdin).get('active'))" 2>/dev/null; }
N=0
for i in $(seq 1 30); do N=$(rps_json | python3 -c "import sys,json
try: print(len(json.load(sys.stdin).get('rps',[])))
except Exception: print(0)"); [ "$N" -ge 2 ] && break; sleep 1; done
if [ "${AUTO_APPROVE:-0}" = "1" ]; then
  for i in $(seq 1 60); do
    for arid in $(rps_json | python3 -c "import sys,json
try: [print(r['arid']) for r in json.load(sys.stdin).get('rps',[]) if r.get('status')=='pending']
except Exception: pass"); do printf -- "approve %s… -> " "${arid:0:10}"; curl -s -m 15 "${CACERT[@]}" -X POST -H "$HDR" "$CIA_SRV/cia/rps/$arid/approve" | python3 -c "import sys,json
try: d=json.load(sys.stdin); print(d.get('status') or list(d)[:2])
except Exception: print('(응답 없음)')"; done
    [ "$(active $RP1:$RP1_PORT)" = "True" ] && [ "$(active $RP2:$RP2_PORT)" = "True" ] && { echo "zkONE·zkTWO active"; break; }
    sleep 2
  done
else
  echo "RP 등록 $N 건 — 인증서 대기(pending). $IDP_PAGE/rp 에서 운영자 계정을 만들고 '새 RP 만들기' 에 같은 이름·주소(zkONE $RP1_UI, zkTWO $RP2_UI)를 넣은 뒤 '인증서 발급 요청' → $SCHEME://$IDP:$IDP_PORT/admin 에서 승인하세요 (2026-11-06; 바로 /admin 승인·AUTO_APPROVE=1 도 된다)."
fi

# 8. 요약
for u in $([ "$ZW" = 1 ] || echo "$IDP:$IDP_PORT") "127.0.0.1:$USER_PORT" "$RP1:$RP1_PORT" "$RP2:$RP2_PORT"; do printf -- "--- %s " "$u"; curl -s -m 10 "${CACERT[@]}" "$SCHEME://$u/mode3/health" | python3 -c "import sys,json;d=json.load(sys.stdin);print({k:d.get(k) for k in ('role','ok','status','secrets','registered','accounts','pendingRps','active') if d.get(k) is not None})"; done
printf -- "--- 체인 구성: "; curl -s -m 5 "${CACERT[@]}" "$CIA_SRV/cia/public_keys" | python3 -c "import sys,json;d=json.load(sys.stdin);print('캐노니컬 chainId', d.get('canonicalChainId'), '· 거울', [m.get('chainId') for m in d.get('mirrors',[])])"
echo "SPLIT_DONE $(date '+%H:%M:%S')"
[ "$ZW" = 1 ] || echo "페이지: IdP 사용자 $IDP_PAGE/user  IdP RP 운영자 $IDP_PAGE/rp  지갑 $WALLET_ORIGIN/  zkONE $RP1_UI/ (관리자 /admin)  zkTWO $RP2_UI/  IdP 관리자 $IDP_PAGE/admin"
echo "새 RP: $IDP_PAGE/rp 에서 운영자 가입 → '새 RP 만들기' → 받은 키로 bash scripts/new_rp.sh <name> <port> <key> --host <RP VM IP>"
if [ "$WALLET_MODE" = "snap" ]; then
  echo "Snap 모드: 브라우저에 MetaMask Flask 가 있어야 한다. 지갑 페이지 $WALLET_ORIGIN/ 에서 MetaMask 연결 → Snap(local:http://localhost:$SNAP_PORT) 설치/재연결."
  echo "         Snap 번들이 바뀌었으면 MetaMask 의 기존 Snap 을 지우고 다시 설치할 것 — 체크섬이 다르면 자동으로 갱신되지 않는다."
  echo "         체인·IdP 가 새로 시작됐으므로 MetaMask 안의 옛 등록은 지갑 페이지의 'Snap 초기화' 로 지운 뒤 다시 등록할 것."
fi
if [ "$WALLET_MODE" = "passkey" ]; then
  echo "패스키 모드: MetaMask 가 필요 없다. 지갑 페이지는 반드시 $WALLET_ORIGIN/ (localhost) 로 연다 — '패스키 만들기' 또는 이미 만든 패스키면 '이미 있는 패스키 쓰기'(같은 salt)."
  echo "         IdP·서비스 페이지는 위 127.0.0.1 주소로 연다(localhost 로 열면 그 페이지도 패스키를 부를 수 있다 — 스펙 §2). RP 소셜 로그인은 이 모드에서 쓰지 않는다."
fi
if [ "$ZW" = 1 ]; then
  echo "zkwrapper: 주소 셋 — zkWrapper(홈·지갑·운영자 /rp·관리자 /admin) $WALLET_ORIGIN/  zkONE $RP1_UI/  zkTWO $RP2_UI/  (IdP VM 은 쓰지 않는다)"
  echo "         흐름: 서비스에서 'zk 로그인' → Google 계정 선택 → 패스키(처음이면 만든다). Google 콘솔: 래퍼 전용 클라이언트 ID 의 승인된 리디렉션 URI 에 $GOOGLE_RELAY"
  echo "         체인은 브라우저가 직접 읽는다(http://127.0.0.1:$APP_PORT·:$REV_PORT). 처음이면 bash scripts/zkd_tls_setup.sh(sudo) 뒤 Chrome 을 다시 시작한다."
elif [ "$WALLET_MODE" = passkey-web ]; then
  echo "passkey-web: 주소 넷 — 지갑 $WALLET_ORIGIN/  속성 도구 $WALLET_ORIGIN/attr.html  zkIdP $IDP_UI/user  zkONE $RP1_UI/  zkTWO $RP2_UI/"
  echo "         처음이면 bash scripts/zkd_tls_setup.sh(sudo) 뒤 Chrome 을 완전히 다시 시작한다. IP 주소로 열면 패스키가 안 된다 — 반드시 위 이름으로."
  echo "         흐름: 지갑 페이지에서 패스키 만들기 → 속성 도구(커밋먼트) → 서비스(zkONE·zkTWO)에서 zkIdP 로 로그인."
  echo "         서비스의 'Google 로 로그인' 은 리디렉션식이다 — Google 콘솔의 '승인된 리디렉션 URI' 에 $GOOGLE_RELAY 가 있어야 한다(위 'RP 소셜' 줄이 off 면 버튼이 없다)."
  echo "         '일반 OIDC · 비교용' 버튼은 $([ "$PLAIN_OIDC" = 1 ] && echo "켜져 있다 — PLAIN_OIDC=0 으로 끈다" || echo "꺼져 있다(PLAIN_OIDC=$PLAIN_OIDC)"). 네이버 로그인은 이 모드에서 쓰지 않는다(localhost 오리진 전용)."
fi
