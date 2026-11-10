// lib/mode3_rp_social.js — RP 의 Google·네이버 로그인과 RP 계정 연결(스펙 2026-11-10-mode3-rp-social-logins §3). mode3_rp.js 가 mountRpSocial(app, …) 로 붙인다.
// 이 로그인은 zk-Delegation 을 거치지 않는다(§6) — RP 가 공급자의 OIDC 클라이언트다. 쿠키 세션은 { rpAccount, via } 만 든다. sub·비밀은 응답에 싣지 않는다.
import { createOidcVerifier, GOOGLE_DEFAULTS } from './mode3_oidc.js';
import { NAVER_DEFAULTS, createOnceStore, pkcePair, naverAuthorizeUrl, exchangeNaverCode, randomHex } from './mode3_oidc_link.js';
import { AccountError } from './mode3_rp_accounts.js';

export const RP_LOGIN_PREFIX = 'rplogin:';
export const RP_LINK_PREFIX = 'rplink:';
const prefixOf = (purpose) => (purpose === 'link' ? RP_LINK_PREFIX : RP_LOGIN_PREFIX);

/** env → 공급자 설정. Google 은 클라이언트 ID 만 있으면, 네이버는 ID·Secret 둘 다 있어야 켜진다. 콜백 기본값은 이 RP 의 공개 주소. */
export function socialConfigFromEnv(env, { publicOrigin }) {
  const gId = env.MODE3_RP_GOOGLE_CLIENT_ID || null, nId = env.MODE3_RP_NAVER_CLIENT_ID || null, nSec = env.MODE3_RP_NAVER_CLIENT_SECRET || null;
  return {
    google: { enabled: Boolean(gId), clientId: gId, issuer: env.MODE3_RP_GOOGLE_ISSUER || GOOGLE_DEFAULTS.issuer, jwksUrl: env.MODE3_RP_GOOGLE_JWKS_URL || GOOGLE_DEFAULTS.jwksUrl },
    naver: {
      enabled: Boolean(nId && nSec), clientId: nId, clientSecret: nSec,
      issuer: env.MODE3_RP_NAVER_ISSUER || NAVER_DEFAULTS.issuer, jwksUrl: env.MODE3_RP_NAVER_JWKS_URL || NAVER_DEFAULTS.jwksUrl,
      authorizeUrl: env.MODE3_RP_NAVER_AUTHORIZE_URL || NAVER_DEFAULTS.authorizeUrl, tokenUrl: env.MODE3_RP_NAVER_TOKEN_URL || NAVER_DEFAULTS.tokenUrl,
      redirectUri: env.MODE3_RP_NAVER_REDIRECT_URI || `${publicOrigin}/api/rp/naver/callback`,
    },
  };
}

/** 쿠키 세션을 계정에 묶는다 — 계정이 정해지는 로그인은 세션 id 를 새로 받는다(고정 공격 방지). */
export function setRpSession(req, account, via) {
  return new Promise((resolve, reject) => req.session.regenerate((e) => {
    if (e) return reject(e);
    req.session.rpAccount = account; req.session.via = via;
    req.session.save((e2) => (e2 ? reject(e2) : resolve()));
  }));
}

/** 네이버에서 돌아갈 곳 — 로그인은 첫 화면, 연결은 "내 계정" 패널. */
const backTo = (purpose, params) => `/?${new URLSearchParams(params)}${purpose === 'link' ? '#account' : ''}`;

export function mountRpSocial(app, { store, cfg, ledgerOp, onLogin = () => {} }) {
  const google = cfg.google.enabled ? createOidcVerifier({ issuer: cfg.google.issuer, jwksUrl: cfg.google.jwksUrl, clientId: cfg.google.clientId }) : null;
  const naver = cfg.naver.enabled ? createOidcVerifier({ issuer: cfg.naver.issuer, jwksUrl: cfg.naver.jwksUrl, clientId: cfg.naver.clientId }) : null;
  const once = createOnceStore({ max: 2000 });
  const jsonOnly = (req, res, next) => (req.is('application/json') ? next() : res.status(415).json({ ok: false, reason: 'json_only' }));
  const me = (req) => (req.session?.rpAccount && store.get(req.session.rpAccount) ? req.session.rpAccount : null);
  const fail = (res, e) => {
    if (e instanceof AccountError) return res.status(e.status).json({ ok: false, reason: e.reason });
    if (e?.reason === 'oidc_unavailable') return res.status(502).json({ ok: false, reason: e.reason });
    if (e?.reason) return res.status(401).json({ ok: false, reason: e.reason });
    return res.status(500).json({ ok: false, reason: 'internal', detail: e?.message });
  };
  /** login: 그 수단의 계정(없으면 새로)으로 세션. link: 시작 때의 계정과 지금 세션 계정이 같을 때 그 계정에 붙인다. */
  async function finish(req, { method, sub, purpose, account }) {
    if (purpose === 'link') {
      if (!account || me(req) !== account) throw new AccountError(401, 'no_rp_session');
      store.link(account, method, { sub });
      return { ok: true, linked: method, via: req.session.via, ...store.view(account) };
    }
    const { id, created } = store.loginOrCreate(method, { sub });
    await setRpSession(req, id, method);
    onLogin({ account: id, via: method, created });
    return { ok: true, created, via: method, ...store.view(id) };
  }

  app.get('/api/rp/me', (req, res) => {
    const id = me(req);
    if (!id) return res.status(401).json({ ok: false, reason: 'no_rp_session' });
    res.json({ ok: true, via: req.session.via, ...store.view(id) });
  });
  app.post('/api/rp/oidc/nonce', jsonOnly, (req, res) => {
    const purpose = req.body?.purpose;
    if (purpose !== 'login' && purpose !== 'link') return res.status(400).json({ ok: false, reason: 'bad_purpose' });
    const account = purpose === 'link' ? me(req) : null;
    if (purpose === 'link' && !account) return res.status(401).json({ ok: false, reason: 'no_rp_session' });
    const nonce = prefixOf(purpose) + randomHex();
    once.put(`nonce:${nonce}`, { purpose, account });
    res.json({ ok: true, nonce });
  });
  app.post('/api/rp/google', jsonOnly, async (req, res) => {
    try {
      if (!google) return res.status(503).json({ ok: false, reason: 'provider_disabled' });
      const { id_token, purpose } = req.body ?? {};
      if (purpose !== 'login' && purpose !== 'link') return res.status(400).json({ ok: false, reason: 'bad_purpose' });
      if (typeof id_token !== 'string' || id_token.length > 8192) return res.status(400).json({ ok: false, reason: 'malformed' });
      const v = await google.verify(id_token, { noncePrefix: prefixOf(purpose) });
      const n = once.take(`nonce:${v.nonce}`);
      if (!n || n.purpose !== purpose) return res.status(401).json({ ok: false, reason: 'bad_nonce' });
      res.json(await finish(req, { method: 'google', sub: v.sub, purpose, account: n.account }));
    } catch (e) { fail(res, e); }
  });
  app.get('/api/rp/naver/start', (req, res) => {
    const purpose = req.query.purpose === 'link' ? 'link' : 'login';
    if (!naver) return res.redirect(backTo(purpose, { social_error: 'provider_disabled' }));
    const account = purpose === 'link' ? me(req) : null;
    if (purpose === 'link' && !account) return res.redirect(backTo(purpose, { social_error: 'no_rp_session' }));
    const st = randomHex(), nonce = prefixOf(purpose) + randomHex(), { verifier, challenge } = pkcePair();
    once.put(`naver-state:${st}`, { purpose, nonce, verifier, account });
    res.redirect(naverAuthorizeUrl(cfg.naver, { state: st, nonce, challenge }));
  });
  app.get('/api/rp/naver/callback', async (req, res) => {
    const st = typeof req.query.state === 'string' ? req.query.state : '';
    const rec = st ? once.take(`naver-state:${st}`) : null;
    if (!rec) return res.redirect(backTo('login', { social_error: 'naver_state_invalid' }));
    if (typeof req.query.error === 'string') return res.redirect(backTo(rec.purpose, { social_error: 'naver_denied' }));
    try {
      const idToken = await exchangeNaverCode(cfg.naver, { code: String(req.query.code ?? ''), state: st, verifier: rec.verifier });
      const v = await naver.verify(idToken, { noncePrefix: prefixOf(rec.purpose) });
      if (v.nonce !== rec.nonce) return res.redirect(backTo(rec.purpose, { social_error: 'bad_nonce' }));
      await finish(req, { method: 'naver', sub: v.sub, purpose: rec.purpose, account: rec.account });
      res.redirect(backTo(rec.purpose, rec.purpose === 'link' ? { linked: 'naver' } : { social: 'ok', via: 'naver' }));
    } catch (e) {
      res.redirect(backTo(rec.purpose, { social_error: e?.reason ?? 'internal' }));
    }
  });
  app.post('/api/rp/unlink', jsonOnly, (req, res) => {
    const id = me(req);
    if (!id) return res.status(401).json({ ok: false, reason: 'no_rp_session' });
    try { store.unlink(id, req.body?.method); res.json({ ok: true, via: req.session.via, ...store.view(id) }); } catch (e) { fail(res, e); }
  });
  app.post('/api/rp/logout', (req, res) => { if (!req.session) return res.json({ ok: true }); req.session.destroy(() => res.json({ ok: true })); });
  app.post('/api/rp/ledger', jsonOnly, async (req, res) => {
    const id = me(req);
    if (!id) return res.status(401).json({ ok: false, reason: 'no_rp_session' });
    try { const r = await ledgerOp({ account: id, body: req.body?.body, channel: 'cookie' }); res.status(r.status ?? 200).json(r.body); } catch (e) { fail(res, e); }
  });
}
