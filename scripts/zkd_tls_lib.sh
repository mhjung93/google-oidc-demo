#!/usr/bin/env bash
# passkey-web 데모용 TLS 도우미(2026-11-17). source 해서 쓴다 — zkd_tls_setup.sh 와 tests/test_zkd_tls_certs.mjs 가 부른다.
# 데모 CA 는 이름 제약(zkd.test·127.0.0.0/8·데모 망)을 달아, 키가 새어도 다른 사이트를 사칭하지 못하게 한다.
# 모든 함수는 umask 077 로 만들고 개인키 내용을 출력하지 않는다. Ubuntu 20.04(OpenSSL 1.1.1)에서 쓰도록 -addext 대신 mktemp 설정 파일을 쓴다.

ZKD_HOSTS_BEGIN='# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>'
ZKD_HOSTS_END='# <<< zkd-demo <<<'

# zkd_ca_create <ca_dir> <demo_net> — 이미 있으면 재사용(이름 제약의 망이 다르면 종료 2)
zkd_ca_create() {
  local dir="$1" net="$2"
  ( umask 077
    mkdir -p "$dir" && chmod 700 "$dir" || exit 1
    if [ -f "$dir/ca.crt" ] && [ -f "$dir/ca.key" ]; then
      if ! openssl x509 -noout -text -in "$dir/ca.crt" | grep -q "IP:$net/255.255.255.0"; then
        echo "기존 CA 의 이름 제약 망이 $net 과 다르다 — $dir 를 지우고 다시 만들거나 ZKD_DEMO_NET 을 맞춘다" >&2
        exit 2
      fi
      exit 0
    fi
    cfg=$(mktemp) || exit 1
    trap 'rm -f "$cfg"' EXIT
    cat > "$cfg" <<CFG
[req]
distinguished_name = dn
prompt = no
x509_extensions = ca_ext
[dn]
CN = zkd demo CA
[ca_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
nameConstraints = critical,permitted;DNS:zkd.test,permitted;IP:127.0.0.0/255.0.0.0,permitted;IP:$net/255.255.255.0
CFG
    openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca.key" 2>/dev/null || exit 1
    chmod 600 "$dir/ca.key"
    openssl req -new -x509 -key "$dir/ca.key" -days 3650 -config "$cfg" -out "$dir/ca.crt" || exit 1
  )
}

# zkd_issue_cert <ca_dir> <out_dir> <short> <dns> <ip>... — 30일 서버 인증서
zkd_issue_cert() {
  local ca="$1" out="$2" short="$3" dns="$4"; shift 4
  ( umask 077
    mkdir -p "$out" && chmod 700 "$out" || exit 1
    cfg=$(mktemp) || exit 1
    csr=$(mktemp) || exit 1
    trap 'rm -f "$cfg" "$csr"' EXIT
    san="DNS:$dns"
    for ip in "$@"; do san="$san,IP:$ip"; done
    cat > "$cfg" <<CFG
[req]
distinguished_name = dn
prompt = no
[dn]
CN = $dns
[srv_ext]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = $san
CFG
    openssl ecparam -name prime256v1 -genkey -noout -out "$out/$short.key" 2>/dev/null || exit 1
    chmod 600 "$out/$short.key"
    openssl req -new -key "$out/$short.key" -config "$cfg" -out "$csr" || exit 1
    openssl x509 -req -in "$csr" -CA "$ca/ca.crt" -CAkey "$ca/ca.key" -CAserial "$ca/ca.srl" -CAcreateserial \
      -days 30 -extfile "$cfg" -extensions srv_ext -out "$out/$short.crt" 2>/dev/null || exit 1
  )
}

# zkd_ca_fingerprint <ca_dir> — SHA-256 지문 한 줄
zkd_ca_fingerprint() {
  openssl x509 -noout -fingerprint -sha256 -in "$1/ca.crt" | sed 's/^[^=]*=//'
}

# zkd_hosts_render <hosts_file> <ip>=<name>... — 표시 블록을 하나로 바꾼(없으면 끝에 더한) 전체 내용을 stdout 으로
zkd_hosts_render() {
  local file="$1"; shift
  local pair
  { awk -v b="$ZKD_HOSTS_BEGIN" -v e="$ZKD_HOSTS_END" '
      $0 == b { skip = 1; next }
      skip && $0 == e { skip = 0; next }
      !skip { print }
    ' "$file"
    echo "$ZKD_HOSTS_BEGIN"
    for pair in "$@"; do echo "${pair%%=*} ${pair#*=}"; done
    echo "$ZKD_HOSTS_END"
  }
}
