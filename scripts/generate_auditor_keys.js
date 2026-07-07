
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import fs from 'fs';
import path from 'path';

const KEYS_FILE = 'auditor_keys.json';

function generateKeys() {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey);

  const keys = {
    AUDITOR_SK: bytesToHex(privateKey),
    AUDITOR_PK: bytesToHex(publicKey),
  };

  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
  console.log(`[keys] New auditor key pair generated and saved to ${KEYS_FILE}`);
  return keys;
}

function getKeys() {
  if (fs.existsSync(KEYS_FILE)) {
    console.log(`[keys] Found existing auditor key file: ${KEYS_FILE}`);
    const content = fs.readFileSync(KEYS_FILE, 'utf-8');
    const keys = JSON.parse(content);
    
    // Validate format
    if (!keys.AUDITOR_SK || !keys.AUDITOR_PK || keys.AUDITOR_SK.length !== 64 || keys.AUDITOR_PK.length !== 130) {
        console.error(`[keys] ${KEYS_FILE} is corrupted or in a wrong format. Generating new keys.`);
        return generateKeys();
    }
    return keys;

  } else {
    return generateKeys();
  }
}

try {
  const keys = getKeys();
  console.log(`[keys] Auditor Public Key: ${keys.AUDITOR_PK}`);
} catch (error) {
  console.error('[keys] An error occurred:', error);
  process.exit(1);
}
