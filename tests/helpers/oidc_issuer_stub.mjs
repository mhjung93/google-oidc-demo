// tests/helpers/oidc_issuer_stub.mjs — 테스트용 RS256 OIDC 발급자(스펙 2026-10-16 D7). JWKS 와 토큰 발행만 한다. 모든 응답에 CORS * —
// 브라우저 테스트의 GIS 스텁이 페이지에서 직접 /mint 를 부른다. 기동마다 새 키.
import http from 'node:http';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';

export async function startOidcIssuerStub({ clientId = 'mode3-test-client', provider = 'stub' } = {}) {
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
  const server = http.createServer(async (req, res) => {
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' };
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
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
  return { base, issuer: base, jwksUrl: `${base}/.well-known/jwks.json`, clientId, provider, mint, stop: () => new Promise((r) => server.close(() => r())) };
}
