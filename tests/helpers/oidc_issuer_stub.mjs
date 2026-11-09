// tests/helpers/oidc_issuer_stub.mjs — 테스트용 RS256 OIDC 발급자(스펙 2026-10-16 D7). JWKS 와 토큰 발행만 한다. 모든 응답에 CORS * —
// 브라우저 테스트의 GIS 스텁이 페이지에서 직접 /mint 를 부른다. 기동마다 새 키.
import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';

// 네이버 흉내(2026-11-09 연결 로그인): /oauth2/authorize 는 로그인 화면 없이 바로 redirect_uri 로 code 를 돌려주고(누가 로그인했는지는
// setNextSub 로 정한다), /oauth2/token 은 client_secret·redirect_uri·PKCE(code_verifier)를 확인해 인가 때의 nonce 를 담은 id_token 을 준다.
export async function startOidcIssuerStub({ clientId = 'mode3-test-client', provider = 'stub', clientSecret = 'stub-secret' } = {}) {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const kid = 'stub-' + Date.now().toString(36);
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  let base = null;
  // omitClaims: 'iat'·'exp' 를 빼고 서명한다(검증기의 requiredClaims 테스트용). 기본은 둘 다 넣는다.
  async function mint({ sub, nonce, aud = clientId, iss = base, expSeconds = 300, extra = {}, omitClaims = [] }) {
    const now = Math.floor(Date.now() / 1000);
    const claims = { sub, ...(nonce === undefined ? {} : { nonce }), ...extra };
    const jwt = new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid }).setIssuer(iss).setAudience(aud);
    if (!omitClaims.includes('iat')) jwt.setIssuedAt(now);
    if (!omitClaims.includes('exp')) jwt.setExpirationTime(now + expSeconds);
    return jwt.sign(privateKey);
  }
  let nextSub = 'stub-sub';
  const codes = new Map();   // code → { sub, nonce, challenge, redirectUri }
  const b64u = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const server = http.createServer(async (req, res) => {
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' };
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
    if (req.method === 'GET' && req.url.startsWith('/oauth2/authorize?')) {
      const q = new URL(req.url, base).searchParams;
      const back = new URL(q.get('redirect_uri'));
      if (q.get('client_id') !== clientId || q.get('response_type') !== 'code' || q.get('code_challenge_method') !== 'S256') { back.searchParams.set('error', 'invalid_request'); }
      else { const code = randomBytes(16).toString('hex'); codes.set(code, { sub: nextSub, nonce: q.get('nonce'), challenge: q.get('code_challenge'), redirectUri: q.get('redirect_uri') }); back.searchParams.set('code', code); }
      back.searchParams.set('state', q.get('state') ?? '');
      res.writeHead(302, { Location: back.toString() }); return res.end();
    }
    if (req.method === 'POST' && req.url === '/oauth2/token') {
      let body = ''; for await (const c of req) body += c;
      const p = new URLSearchParams(body), c = codes.get(p.get('code'));
      codes.delete(p.get('code'));
      const ok = c && p.get('grant_type') === 'authorization_code' && p.get('client_id') === clientId && p.get('client_secret') === clientSecret
        && p.get('redirect_uri') === c.redirectUri && b64u(createHash('sha256').update(p.get('code_verifier') ?? '').digest()) === c.challenge;
      if (!ok) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: 'invalid_grant' })); }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ access_token: 'stub-access', token_type: 'bearer', id_token: await mint({ sub: c.sub, nonce: c.nonce }) }));
    }
    if (req.method === 'GET' && req.url === '/.well-known/jwks.json') { res.writeHead(200, { ...cors, 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ keys: [jwk] })); }
    if (req.method === 'POST' && req.url === '/mint') {
      let body = ''; for await (const c of req) body += c;
      try { const id_token = await mint(JSON.parse(body || '{}')); res.writeHead(200, { ...cors, 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ id_token })); }
      catch (e) { res.writeHead(400, { ...cors, 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: e.message })); }
    }
    res.writeHead(404, cors); res.end();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  return { base, issuer: base, jwksUrl: `${base}/.well-known/jwks.json`, authorizeUrl: `${base}/oauth2/authorize`, tokenUrl: `${base}/oauth2/token`, clientId, clientSecret, provider, mint,
    setNextSub: (s) => { nextSub = s; }, stop: () => new Promise((r) => server.close(() => r())) };
}
