#!/usr/bin/env bash
# passkey-web 데모 TLS 최초 1회 준비(2026-11-17) — 사용자가 직접 실행한다(sudo 로 /etc/hosts 를 고치고 Chrome 의 NSS 저장소에 CA 를 넣는다).
#   1) libnss3-tools(certutil) 설치  2) /etc/hosts 의 zkd-demo 블록  3) 데모 CA 만들기/재사용  4) Chrome NSS 에 CA 신뢰 등록
# 주소: SPLIT_IDP_IP·SPLIT_RP1_IP·SPLIT_RP2_IP(기본 demo_split_start.sh 와 같은 .10/.11/.12), CA 위치 ZKD_CA_DIR(기본 .local/zkd-ca), 데모 망 ZKD_DEMO_NET(기본 192.168.226.0)
set -euo pipefail
if [ "$(id -u)" -eq 0 ]; then echo "BLOCKED: sudo 없이 실행하세요 — 필요한 단계에서만 sudo 를 묻습니다" >&2; exit 2; fi
cd "$(dirname "$0")/.."
# shellcheck source=scripts/zkd_tls_lib.sh
source scripts/zkd_tls_lib.sh
umask 077

IDP="${SPLIT_IDP_IP:-192.168.226.10}"; RP1="${SPLIT_RP1_IP:-192.168.226.11}"; RP2="${SPLIT_RP2_IP:-192.168.226.12}"
CA_DIR="${ZKD_CA_DIR:-.local/zkd-ca}"; NET="${ZKD_DEMO_NET:-192.168.226.0}"
NSSDB="$HOME/.pki/nssdb"

if command -v certutil >/dev/null 2>&1; then
  echo "[건너뜀] certutil 이미 있음"
else
  sudo apt-get update
  sudo apt-get install -y libnss3-tools
  echo "[했음] libnss3-tools 설치"
fi

new_hosts=$(mktemp); trap 'rm -f "$new_hosts"' EXIT
if ! zkd_hosts_render /etc/hosts "127.0.0.1=wallet.zkd.test" "$IDP=idp.zkd.test" "$RP1=zkone.zkd.test" "$RP2=zktwo.zkd.test" > "$new_hosts"; then
  echo "BLOCKED: /etc/hosts 를 건드리지 않고 중단한다" >&2; exit 3
fi
if cmp -s "$new_hosts" /etc/hosts; then
  echo "[건너뜀] /etc/hosts 블록 이미 최신"
else
  sudo install -m 644 "$new_hosts" /etc/hosts
  echo "[했음] /etc/hosts 블록 갱신"
fi

if [ -f "$CA_DIR/ca.crt" ] && [ -f "$CA_DIR/ca.key" ]; then
  zkd_ca_create "$CA_DIR" "$NET"   # 이름 제약 망이 다르면 여기서 종료 2
  echo "[건너뜀] 데모 CA 재사용($CA_DIR)"
else
  zkd_ca_create "$CA_DIR" "$NET"
  echo "[했음] 데모 CA 생성($CA_DIR)"
fi

if [ -f "$NSSDB/cert9.db" ]; then
  echo "[건너뜀] $NSSDB 있음"
else
  mkdir -p "$NSSDB"; chmod 700 "$NSSDB"
  certutil -N --empty-password -d "sql:$NSSDB"
  echo "[했음] $NSSDB 생성"
fi

want_fp=$(zkd_ca_fingerprint "$CA_DIR")
if certutil -L -d "sql:$NSSDB" -n zkd-demo-ca >/dev/null 2>&1; then
  have_fp=$(certutil -L -d "sql:$NSSDB" -n zkd-demo-ca -a | openssl x509 -noout -fingerprint -sha256 | sed 's/^[^=]*=//')
  if [ "$have_fp" = "$want_fp" ]; then
    echo "[건너뜀] zkd-demo-ca 이미 신뢰 등록됨"
  else
    certutil -D -d "sql:$NSSDB" -n zkd-demo-ca
    certutil -A -d "sql:$NSSDB" -t 'C,,' -n zkd-demo-ca -i "$CA_DIR/ca.crt"
    echo "[했음] 옛 zkd-demo-ca 를 지우고 새 CA 로 교체"
  fi
else
  certutil -A -d "sql:$NSSDB" -t 'C,,' -n zkd-demo-ca -i "$CA_DIR/ca.crt"
  echo "[했음] Chrome NSS 에 zkd-demo-ca 등록"
fi

echo "CA SHA-256 지문: $want_fp"
echo "Chrome 을 완전히 종료했다가 다시 여세요."
