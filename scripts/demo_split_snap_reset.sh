#!/usr/bin/env bash
# Mode 3 VM 분리 데모를 Snap 모드로(2026-10-22): IdP·zkONE·zkTWO 는 각자의 VM, 체인 두 개와 지갑 에이전트(:5100, 비밀은 MetaMask Snap)+Snap 서버(:8082)는 이 VM.
# demo_split_start.sh 의 WALLET_MODE=snap. 옵션(AUTO_APPROVE·SYNC·ADMIN_OPEN·HEIGHT_GRID, stop)은 그대로. 포트 5100·8082 를 쓰므로 한 머신 Snap 데모(demo_snap_reset.sh)와 동시에 못 띄운다.
WALLET_MODE=snap exec bash "$(dirname "$0")/demo_split_start.sh" "$@"
