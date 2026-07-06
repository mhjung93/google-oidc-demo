import mcl from 'mcl-wasm';

async function test() {
  await mcl.init(mcl.BLS12_381);
  console.log('MCL exports:', Object.keys(mcl));
}
test();
