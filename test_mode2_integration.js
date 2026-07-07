import fetch from 'node-fetch';

async function testIntegration() {
  console.log('Starting Mode 2 Integration Test...');

  try {
    // 1. RP 정보 확인 (이미 등록되어 있다고 가정하거나 등록 시도)
    console.log('Step 1: Registering RP...');
    const regRes = await fetch('http://localhost:3000/api/mode2/register', { method: 'POST' });
    const rpInfo = await regRes.json();
    console.log('RP Registered:', rpInfo.rid);

    // 2. IdP 로그인 (mock)
    console.log('Step 2: Logging into IdP...');
    const loginRes = await fetch('http://localhost:4000/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'testuser', password: 'password123' })
    });
    const loginData = await loginRes.json();
    console.log('IdP Login success:', loginData.success);

    // 3. SSO 시도 (ZKP 데이터는 mock으로 전달)
    console.log('Step 3: Attempting SSO with credentials + ZKP...');
    const ssoRes = await fetch('http://localhost:4000/sso_with_credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser',
        password: 'password123',
        proof: 'mock-proof',
        publicSignals: {
          r_RP: '0x123',
          arid_i: 'mock-arid',
          auid_i: 'mock-auid'
        }
      })
    });
    const ssoData = await ssoRes.json();
    console.log('IdP SSO success:', ssoData.success);

    // 4. RP에게 IdP Token 전달하여 세션 확립
    console.log('Step 4: Finalizing SSO at RP...');
    const finalRes = await fetch('http://localhost:3000/api/mode2/sso_success', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idpToken: ssoData.idpToken })
    });
    const finalData = await finalRes.json();
    console.log('RP Final SSO success:', finalData.success);

    if (finalData.success) {
      console.log('✅ Integration Test PASSED');
    } else {
      console.log('❌ Integration Test FAILED:', finalData.error);
    }

  } catch (err) {
    console.error('❌ Integration Test Error:', err.message);
  }
}

testIntegration();
