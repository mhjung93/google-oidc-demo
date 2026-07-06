import mcl from 'mcl-wasm';
import { randomBytes } from 'crypto';

async function test() {
  await mcl.init(mcl.BLS12_381);

  // 1. Setup
  const g1 = mcl.hashAndMapToG1('gen1');
  const g2 = mcl.hashAndMapToG2('gen2');

  // 2. KeyGen (n=4)
  const x = new mcl.Fr();
  x.setByCSPRNG();
  const y = [];
  for (let i = 0; i < 4; i++) {
    const yi = new mcl.Fr();
    yi.setByCSPRNG();
    y.push(yi);
  }

  const PK_X = mcl.mul(g2, x);
  const PK_Y = y.map(yi => mcl.mul(g2, yi));

  // 3. Sign
  const messages = ["user-12345", "arid-abc", "auid-def", "1700000000"];
  const h = mcl.hashAndMapToG1(randomBytes(32).toString('hex'));

  let exponent = x.clone();

  function hashToFr(str) {
    const fr = new mcl.Fr();
    fr.setHashOf(str);
    return fr;
  }

  for (let i = 0; i < messages.length; i++) {
    const mi = hashToFr(messages[i]);
    exponent = mcl.add(exponent, mcl.mul(y[i], mi));
  }

  const sigma1 = h;
  const sigma2 = mcl.mul(h, exponent);

  console.log('Signature generated.');

  // 4. Verify
  const s1 = sigma1;
  const s2 = sigma2;

  let PK_total = new mcl.G2();
  PK_total = mcl.add(PK_X, PK_total);
  for (let i = 0; i < messages.length; i++) {
    const mi = hashToFr(messages[i]);
    PK_total = mcl.add(PK_total, mcl.mul(PK_Y[i], mi));
  }

  const lhs = mcl.pairing(s1, PK_total);
  const rhs = mcl.pairing(s2, g2);

  console.log('LHS == RHS?', lhs.isEqual(rhs));
  if (lhs.isEqual(rhs)) {
    console.log('PS Signature Verification Success!');
  } else {
    console.log('PS Signature Verification Failed!');
    process.exit(1);
  }
}

test();
