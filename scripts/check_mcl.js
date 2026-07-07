import mcl from 'mcl-wasm';

async function test() {
  await mcl.init(mcl.BLS12_381);
  const g1 = new mcl.G1();
  console.log(Object.getOwnPropertyNames(Object.getPrototypeOf(g1)));
}
test();
