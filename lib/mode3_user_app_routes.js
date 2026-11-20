// lib/mode3_user_app_routes.js — 사용자 앱(브라우저 지갑)의 페이지·번들·회로·공개 설정 경로(계획 2026-11-20 zkwrapper Task 5).
// 정적 서버(mode3_user_static.js)와 zkWrapper 서버(cia.js, CIA_USER_APP=1)가 함께 쓴다 — 어느 쪽이든 내는 파일과 응답은 같다. 비밀·세션을 받는 경로는 없다.
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
export const USER_DIST = path.join(ROOT, 'mode3', 'user', 'dist');
const ZK = {
  'pi_cred.wasm': 'build/mode3/pi_cred_js/pi_cred.wasm', 'pi_cred_final.zkey': 'build/mode3/pi_cred_final.zkey', 'pi_cred_vkey.json': 'build/mode3/pi_cred_vkey.json',
  'pi_idp.wasm': 'build/mode3/pi_idp_js/pi_idp.wasm', 'pi_idp_final.zkey': 'build/mode3/pi_idp_final.zkey', 'pi_idp_vkey.json': 'build/mode3/pi_idp_vkey.json',
};
/** 번들(mode3/user/dist/user.js)이 있는가 — 없으면 서버가 기동을 거부한다(npm run user:build 먼저). */
export const userDistReady = () => fs.existsSync(path.join(USER_DIST, 'user.js'));
/** 지갑 오리진의 CSP(2026-11-17): 이 서버가 낸 스크립트만 돈다 — 인라인·남의 오리진 스크립트·eval 을 막고, wasm(snarkjs·Poseidon)과 blob: 워커(ffjavascript 스레드)만 허용한다.
 *  connect: 'self' 말고 이 페이지가 직접 부르는 오리진들(발급 서버·서비스·체인 노드). */
export function userAppCsp(connect = []) {
  return [
    "default-src 'self'", "script-src 'self' 'wasm-unsafe-eval'", "worker-src 'self' blob:", `connect-src ${["'self'", ...new Set(connect)].join(' ')}`,
    "img-src 'self' data:", "style-src 'self' 'unsafe-inline'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'none'",
  ].join('; ');
}
/** 사용자 앱의 경로를 app 에 붙인다. config(): /user/config 의 본문(부를 때마다 — 서비스 목록이 바뀔 수 있다). csp: 문자열 또는 () => 문자열 — 주면 **이 경로들의 응답에만** 단다
 *  (같은 서버의 다른 페이지 — 관리자 화면 등 — 에는 달지 않는다. 워커 스크립트는 자기 응답의 정책을 따르므로 /dist 에도 단다). */
export function mountUserApp(app, { config, csp = null }) {
  const guard = (req, res, next) => { if (csp) res.set('Content-Security-Policy', typeof csp === 'function' ? csp() : csp); next(); };
  const file = (...p) => (req, res) => res.sendFile(path.join(ROOT, ...p));
  app.get('/', guard, file('mode3', 'user', 'index.html'));
  app.use('/dist', guard, express.static(USER_DIST));
  app.use('/common', guard, express.static(path.join(ROOT, 'mode3', 'common')));
  // 속성 커밋먼트 도구 — 이 서버의 어떤 API 도 부르지 않는 독립 정적 페이지.
  app.get('/attr.html', guard, file('mode3', 'attr.html'));
  // Google 로그인 중계(2026-11-19): Google 이 받는 "돌아올 주소" 는 공개 도메인이나 localhost 뿐이라 이 서버의 /google-relay 를 등록한다 — 이 화면이 조각(#)에 실려 온
  // ID 토큰을 그 로그인을 시작한 창(서비스 페이지 또는 지갑 창)으로 넘긴다. 이 서버는 토큰을 보지 않는다(조각은 서버에 오지 않는다).
  app.get('/google-relay', guard, file('mode3', 'user', 'google_relay.html'));
  app.get('/google-relay.js', guard, file('mode3', 'user', 'google_relay.js'));
  app.use('/attr', guard, express.static(path.join(ROOT, 'mode3', 'attr'), { index: false }));
  app.get('/zk/:name', guard, (req, res) => {
    const rel = ZK[req.params.name];
    if (!rel) return res.status(404).json({ reason: 'not_found' });
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    res.sendFile(path.join(ROOT, rel), (err) => { if (err && !res.headersSent) res.status(err.statusCode === 404 ? 404 : 500).json({ reason: err.statusCode === 404 ? 'zk_assets_unavailable' : 'internal' }); });
  });
  app.get('/user/config', guard, (req, res) => res.json(config()));
}
