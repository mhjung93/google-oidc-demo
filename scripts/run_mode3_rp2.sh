#!/usr/bin/env bash
# 두 번째 Mode 3 서비스(RP #2) — 같은 사용자가 서비스마다 다른 PPID 계정을 받는 것을 보이는 데모용(2026-09-30, docs/MODE3_DEMO.md "두 번째 서비스").
# 첫 서비스(:3100)와 겹치지 않게 포트·이름·오리진·등록 파일·로그인 로그·릴레이어 계정을 바꾼다. 지갑은 MODE3_RP_ORIGIN 에 이 오리진을 더해 띄운다.
# 나머지(CIA 주소, 로그 컨트랙트, 검증자 주소 등)는 .env / 현재 셸 환경을 그대로 쓴다. 인자로 넘긴 KEY=VALUE 는 덮어쓴다.
set -euo pipefail
cd "$(dirname "$0")/.."
export MODE3_RP_PORT="${MODE3_RP_PORT:-3101}"
export MODE3_RP_NAME="${MODE3_RP_NAME:-demo-rp2}"
export MODE3_RP_PUBLIC_ORIGIN="${MODE3_RP_PUBLIC_ORIGIN:-http://127.0.0.1:${MODE3_RP_PORT}}"
export MODE3_RP_REGISTRATION_FILE="${MODE3_RP_REGISTRATION_FILE:-mode3_rp2_registration.json}"
export MODE3_RP_LOGIN_LOG="${MODE3_RP_LOGIN_LOG:-mode3_rp2_logins.jsonl}"
export MODE3_RELAYER_INDEX="${MODE3_RELAYER_INDEX:-1}"
# 정책을 첫 서비스와 다르게 두면 "서비스마다 정책이 다르다" 까지 보인다(둘 다 비우면 mode3_rp.js 기본값).
export MODE3_ALLOWED_COUNTRIES="${MODE3_ALLOWED_COUNTRIES:-410,392}"
export MODE3_MIN_AGE="${MODE3_MIN_AGE:-19}"
for kv in "$@"; do export "$kv"; done
echo "[rp2] :${MODE3_RP_PORT} name=${MODE3_RP_NAME} origin=${MODE3_RP_PUBLIC_ORIGIN} reg=${MODE3_RP_REGISTRATION_FILE} relayer=${MODE3_RELAYER_INDEX}"
echo "[rp2] 지갑은 MODE3_RP_ORIGIN=http://127.0.0.1:3100,${MODE3_RP_PUBLIC_ORIGIN} 로 띄워야 한다"
exec node mode3_rp.js
