// 세 서버(cia.js·mode3_rp.js·mode3_user_static.js)의 선택적 TLS 기동 — MODE3_TLS_CERT·MODE3_TLS_KEY 가 있으면 https.
// 설계: passkey-web(설치 없는 패스키 모드)은 WebAuthn 이 보안 컨텍스트(https)를 요구해 데모 서버가 TLS 로 떠야 한다.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';

/** 환경변수에서 TLS 옵션을 만든다. 둘 다 비면 null(http), 하나만 있으면 오류. 오류 메시지에는 경로만 담는다(파일 내용 금지). */
export function tlsOptionsFromEnv(env = process.env) {
  const certPath = env.MODE3_TLS_CERT || '';
  const keyPath = env.MODE3_TLS_KEY || '';
  if (!certPath && !keyPath) return null;
  if (!certPath || !keyPath) throw new Error('MODE3_TLS_CERT·MODE3_TLS_KEY 는 함께 지정해야 한다');
  const read = (name, p) => {
    try { return fs.readFileSync(p); } catch { throw new Error(`${name} 를 읽을 수 없다: ${p}`); }
  };
  return { cert: read('MODE3_TLS_CERT', certPath), key: read('MODE3_TLS_KEY', keyPath) };
}

/** app.listen 대용 — TLS 설정이 있으면 https 서버, 없으면 http 서버로 listen 한다. */
export function listenMaybeTls(app, { port, host, env = process.env, onListening } = {}) {
  const tls = tlsOptionsFromEnv(env);
  const scheme = tls ? 'https' : 'http';
  const server = tls ? https.createServer(tls, app) : http.createServer(app);
  server.listen(port, host, () => { if (onListening) onListening(scheme); });
  return { server, scheme };
}
