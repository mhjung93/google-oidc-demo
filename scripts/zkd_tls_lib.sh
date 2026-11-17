#!/usr/bin/env bash
# passkey-web 데모용 TLS 도우미(2026-11-17). source 해서 쓴다 — zkd_tls_setup.sh 와 tests/test_zkd_tls_certs.mjs 가 부른다.
# 데모 CA 는 이름 제약(zkd.test·127.0.0.0/8·데모 망)을 달아, 키가 새어도 다른 사이트를 사칭하지 못하게 한다.
# 모든 함수는 umask 077 로 만들고 개인키 내용을 출력하지 않는다. Ubuntu 20.04(OpenSSL 1.1.1)에서 쓰도록 -addext 대신 mktemp 설정 파일을 쓴다.

ZKD_HOSTS_BEGIN='# >>> zkd-demo (scripts/zkd_tls_setup.sh) >>>'
ZKD_HOSTS_END='# <<< zkd-demo <<<'

# zkd_ca_dir_check <ca_dir> — CA 디렉터리가 git 작업 트리 안이면 ca.key 가 .gitignore 에 걸려야 한다(아니면 BLOCKED, 2).
# 공개 저장소에 CA 개인키가 커밋·푸시되지 않게 한다. git 이 없거나 작업 트리 밖이면 검사하지 않는다. 디렉터리는 만들지 않는다.
zkd_ca_dir_check() {
  local dir="$1" abs probe
  command -v git >/dev/null 2>&1 || return 0
  abs=$(realpath -m -- "$dir") || return 1
  probe="$abs"
  while [ ! -d "$probe" ]; do probe=$(dirname -- "$probe"); done
  [ "$(git -C "$probe" rev-parse --is-inside-work-tree 2>/dev/null)" = true ] || return 0
  if ! git -C "$probe" check-ignore -q -- "$abs/ca.key"; then
    echo "BLOCKED: CA 위치 $dir 가 git 저장소 안인데 .gitignore 에 걸리지 않는다 — ca.key 가 커밋될 수 있다. .gitignore 에 넣거나 ZKD_CA_DIR 을 저장소 밖으로" >&2
    return 2
  fi
}

# zkd_ca_create <ca_dir> <demo_net> — 이미 있으면 재사용(이름 제약의 망이 다르면 종료 2, 저장소 안인데 ignore 안 됐으면 종료 2)
zkd_ca_create() {
  local dir="$1" net="$2"
  zkd_ca_dir_check "$dir" || return $?
  ( umask 077
    mkdir -p "$dir" && chmod 700 "$dir" || exit 1
    if [ -f "$dir/ca.crt" ] && [ -f "$dir/ca.key" ]; then
      if ! openssl x509 -noout -text -in "$dir/ca.crt" | grep -qF "IP:$net/255.255.255.0"; then
        echo "BLOCKED: 기존 CA 의 이름 제약 망이 $net 과 다르다 — $dir 를 지우고 다시 만들거나 ZKD_DEMO_NET 을 맞춘다" >&2
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
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CFG
    openssl ecparam -name prime256v1 -genkey -noout -out "$out/$short.key" 2>/dev/null || exit 1
    chmod 600 "$out/$short.key"
    openssl req -new -key "$out/$short.key" -config "$cfg" -out "$csr" || exit 1
    openssl x509 -req -in "$csr" -CA "$ca/ca.crt" -CAkey "$ca/ca.key" -CAserial "$ca/ca.srl" -CAcreateserial \
      -days 30 -extfile "$cfg" -extensions srv_ext -out "$out/$short.crt" || exit 1
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
  # 시작 표시만 있고 끝 표시가 없으면 뒤 내용을 통째로 잃으므로 아무것도 쓰지 않고 3 으로 끝낸다
  if ! awk -v b="$ZKD_HOSTS_BEGIN" -v e="$ZKD_HOSTS_END" '
      $0 == b { skip = 1; next }
      skip && $0 == e { skip = 0; next }
      END { exit skip ? 3 : 0 }
    ' "$file"; then
    echo "BLOCKED: $file 에 zkd-demo 시작 표시만 있고 끝 표시가 없다 — 직접 고친 뒤 다시 실행한다" >&2
    return 3
  fi
  # 호출하는 쪽이 `if !` 안에서 부르면 errexit 가 꺼지므로, 단계마다 실패를 직접 돌려준다(블록만 남은 출력이 /etc/hosts 를 덮지 않게)
  zkd_hosts_strip "$file" || return 1
  echo "$ZKD_HOSTS_BEGIN" || return 1
  for pair in "$@"; do echo "${pair%%=*} ${pair#*=}" || return 1; done
  echo "$ZKD_HOSTS_END" || return 1
}

# zkd_hosts_strip <hosts_file> — 표시 블록을 뺀 줄들을 stdout 으로
zkd_hosts_strip() {
  awk -v b="$ZKD_HOSTS_BEGIN" -v e="$ZKD_HOSTS_END" '
      $0 == b { skip = 1; next }
      skip && $0 == e { skip = 0; next }
      !skip { print }
    ' "$1"
}

# zkd_hosts_check <원래 hosts> <렌더한 hosts> — 원래 파일의 블록 밖 줄이 렌더 결과에 그대로(순서까지) 남았는지. 아니면 BLOCKED, 1
zkd_hosts_check() {
  local a b
  a=$(zkd_hosts_strip "$1") || { echo "BLOCKED: $1 를 읽지 못했다" >&2; return 1; }
  b=$(zkd_hosts_strip "$2") || { echo "BLOCKED: $2 를 읽지 못했다" >&2; return 1; }
  if [ "$a" != "$b" ]; then
    echo "BLOCKED: 새 hosts 내용에 원래 $1 의 줄이 빠지거나 바뀌었다 — 설치하지 않는다" >&2
    return 1
  fi
}
