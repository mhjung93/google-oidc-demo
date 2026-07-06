import { buildPoseidon } from "circomlibjs";

async function check() {
    const poseidon = await buildPoseidon();
    const hash = poseidon(["12345", "67890", "111222"]);
    console.log("Hash (F.toString):", poseidon.F.toString(hash));
}

check();
