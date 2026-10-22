#!/usr/bin/env bash
# Mode 3 VM 분리 데모 리셋(web 모드, 2026-10-22 이름 정리): demo_split_start.sh 를 그대로 부른다 — 그 스크립트는 부를 때마다 체인·IdP 상태·RP 등록을 새로 만든다(= 리셋).
# 네 명령이 짝을 이룬다: 한 머신 demo_web_reset.sh / demo_snap_reset.sh, 분리 demo_split_reset.sh / demo_split_snap_reset.sh. 옵션(AUTO_APPROVE·SYNC·ADMIN_OPEN·HEIGHT_GRID, stop)은 그대로.
exec bash "$(dirname "$0")/demo_split_start.sh" "$@"
