/**
 * EUDI Wallet Sandbox - Cryptographic E2E Handshake Demo
 * 
 * This script simulates the step sequence of an end-to-end encryption (JWE)
 * in the context of an EUDI wallet transaction.
 * 
 * Sequence:
 * 1. Receiver (RP) generates a static P-256 key pair
 * 2. Sender (Wallet) generates a temporary (ephemeral) P-256 key pair
 * 3. Wallet executes an ECDH key agreement and derives an AES-128 key (Contact KDF)
 * 4. Wallet encrypts the PID data (AES-128-GCM) and generates a JWE (compact 5-segment format)
 * 5. Verifier received JWE, extracts the ephemeral key, calculates the same AES key and decrypts the data
 */

const crypto = require('crypto');

// ANSI escape codes for colored terminak output
const C_RESET = "\x1b[0m";
const C_BOLD = "\x1b[1m";
const C_GREEN = "\x1b[32m";
const C_CYAN = "\x1b[36m";
const C_YELLOW = "\x1b[33m";
const C_RED = "\x1b[31m";

/**
 * Concat KDF (RFC 7518)
 * Derives the symmetric key from the shared ECDH secret
 */
function deriveConcatKDF(sharedSecret, keyLenBytes, alg, apu = null, apv = null) {
  const roundOutputs = [];
  let counter = 1;
  const keyLenBits = keyLenBytes * 8;

  // AlgorithmID: 32-Bit length prefix + algorithm string (ASCII)
  const algBuffer = Buffer.from(alg, 'ascii');
  const algLen = Buffer.alloc(4);
  algLen.writeUInt32BE(algBuffer.length, 0);
  const algorithmID = Buffer.concat([algLen, algBuffer]);

  // PartyUInfo (apu)
  const apuBuffer = apu ? Buffer.from(apu, 'base64url') : Buffer.alloc(0);
  const apuLen = Buffer.alloc(4);
  apuLen.writeUInt32BE(apuBuffer.length, 0);
  const partyUInfo = Buffer.concat([apuLen, apuBuffer]);

  // PartyVInfo (apv)
  const apvBuffer = apv ? Buffer.from(apv, 'base64url') : Buffer.alloc(0);
  const apvLen = Buffer.alloc(4);
  apvLen.writeUInt32BE(apvBuffer.length, 0);
  const partyVInfo = Buffer.concat([apvLen, apvBuffer]);

  // SuppPubInfo: key length in bits (32 bit Big Endian)
  const suppPubInfo = Buffer.alloc(4);
  suppPubInfo.writeUInt32BE(keyLenBits, 0);

  // constructing the "OtherInfo" structure
  const fixedInfo = Buffer.concat([
    algorithmID,
    partyUInfo,
    partyVInfo,
    suppPubInfo
  ]);

  let bytesDerived = 0;
  while (bytesDerived < keyLenBytes) {
    const counterBuffer = Buffer.alloc(4);
    counterBuffer.writeUInt32BE(counter, 0);

    const hash = crypto.createHash('sha256')
      .update(Buffer.concat([counterBuffer, sharedSecret, fixedInfo]))
      .digest();

    roundOutputs.push(hash);
    bytesDerived += hash.length;
    counter++;
  }

  return Buffer.concat(roundOutputs).slice(0, keyLenBytes);
}

async function runDemo() {
  console.log(`${C_BOLD}${C_CYAN}================================================================${C_RESET}`);
  console.log(`${C_BOLD}${C_CYAN}🔐 EUDI WALLET - E2E HANDSHAKE DEMO RUN ${C_RESET}`);
  console.log(`${C_BOLD}${C_CYAN}================================================================${C_RESET}\n`);

  // mock PID data that shall be transmitted
  const rawClaims = {
    given_name: "Erika",
    family_name: "Mustermann",
    birthdate: "1998-08-12",
    is_over_18: true,
    address: {
      street_address: "Heidestraße 17",
      locality: "Köln",
      postal_code: "50667",
      country: "DE"
    }
  };

  console.log(`${C_BOLD}[Step 1] Receiver (Relying Party / Verifier) prepares key...${C_RESET}`);
  // verifier generates its asymmetric key pair
  const rpKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const rpPrivateKey = rpKeyPair.privateKey;
  const rpPublicKeyJwk = rpKeyPair.publicKey.export({ format: 'jwk' });
  console.log(`   ✔ Verifier EC P-256 Public Key generated (kid: "rp-key-1")`);
  console.log(`   ✔ Public X coordinate: ${C_YELLOW}${rpPublicKeyJwk.x}${C_RESET}`);
  console.log(`   ✔ Public Y coordinate: ${C_YELLOW}${rpPublicKeyJwk.y}${C_RESET}\n`);


  console.log(`${C_BOLD}[Step 2] Wallet (Sender) intiates encryption for the transport channel...${C_RESET}`);
  // wallet generates a transient (ephemeral) key for this transaction
  const walletEphemeralKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const epkJwk = walletEphemeralKeyPair.publicKey.export({ format: 'jwk' });
  console.log(`   ✔ Ephemeral Wallet key (epk) generated.`);
  console.log(`   ✔ Ephemeral X coordinate: ${C_YELLOW}${epkJwk.x}${C_RESET}\n`);


  console.log(`${C_BOLD}[Step 3] Wallet executes ECDH...${C_RESET}`);
  // wallet consiserd its provate key and the verifier's public key
  const walletSharedSecret = crypto.diffieHellman({
    privateKey: walletEphemeralKeyPair.privateKey,
    publicKey: crypto.createPublicKey({ key: rpPublicKeyJwk, format: 'jwk' })
  });
  console.log(`   ✔ Shares secret calculated: ${C_GREEN}${walletSharedSecret.toString('hex').slice(0, 32)}... (${walletSharedSecret.length} Bytes)${C_RESET}`);

  // Concat KDF to derive the AES-128-GCM key
  const walletAesKey = deriveConcatKDF(walletSharedSecret, 16, "A128GCM");
  console.log(`   ✔ Symmetric AES-128 key derived via Concat KDF: ${C_GREEN}${walletAesKey.toString('hex')}${C_RESET}\n`);


  console.log(`${C_BOLD}[Step 4] Wallet encrypts PID data (AES-128-GCM)...${C_RESET}`);
  const jweHeader = {
    alg: "ECDH-ES",
    enc: "A128GCM",
    epk: {
      kty: "EC",
      crv: "P-256",
      x: epkJwk.x,
      y: epkJwk.y
    }
  };

  const jweHeaderB64 = Buffer.from(JSON.stringify(jweHeader)).toString('base64url');
  const iv = crypto.randomBytes(12); // GCM demands a 12 byte initialization vector (IV)

  const cipher = crypto.createCipheriv('aes-128-gcm', walletAesKey, iv);
  // JWE header flows into the GCM ecnryption as Additional Authenticated Data (AAD)
  cipher.setAAD(Buffer.from(jweHeaderB64, 'ascii'));

  const payloadBuffer = Buffer.from(JSON.stringify(rawClaims), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(payloadBuffer), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 byte authentication tag for integrity protection

  // concatenate JWE compct format:
  // header . encrypted key (empty in case of ECDH-ES) . IV . cipher text . tag
  const jweCompactString = `${jweHeaderB64}..${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${tag.toString('base64url')}`;

  console.log(`   ✔ Encryption completed.`);
  console.log(`   ✔ Generated JWE token string (transmission-ready):`);
  console.log(`     ${C_YELLOW}${jweCompactString.slice(0, 70)}...[shortened]...${jweCompactString.slice(-30)}${C_RESET}\n`);


  console.log(`${C_BOLD}[Step 5] Verifier receives JWE and starts decryption...${C_RESET}`);
  const jweParts = jweCompactString.split('.');
  if (jweParts.length !== 5) {
    throw new Error("Invalid JWE compact format.");
  }
  const [recHeaderB64, recEncKeyB64, recIvB64, recCiphertextB64, recTagB64] = jweParts;

  // decode header to read the wallet's ephemeral public key
  const recHeader = JSON.parse(Buffer.from(recHeaderB64, 'base64url').toString('utf8'));
  console.log(`   ✔ Read received header. Encryption algorithm: ${C_GREEN}${recHeader.alg} + ${recHeader.enc}${C_RESET}`);

  const walletPublicKey = crypto.createPublicKey({
    key: recHeader.epk,
    format: 'jwk'
  });


  console.log(`${C_BOLD}[Step 6] Verifier calculates counterpart (ECDH-ES)...${C_RESET}`);
  // verifier uses its private key and the extracted ephemeral wallet key
  const verifierSharedSecret = crypto.diffieHellman({
    privateKey: rpPrivateKey,
    publicKey: walletPublicKey
  });
  console.log(`   ✔ Calculated shared secret: ${C_GREEN}${verifierSharedSecret.toString('hex').slice(0, 32)}...${C_RESET}`);

  // verifier executes Concat KDF key derivation
  const verifierAesKey = deriveConcatKDF(verifierSharedSecret, 16, "A128GCM");
  console.log(`   ✔ Verifier derives symmetric AES key: ${C_GREEN}${verifierAesKey.toString('hex')}${C_RESET}`);

  // checking whether the keys are identical
  const keysMatch = walletAesKey.equals(verifierAesKey);
  if (keysMatch) {
    console.log(`   ✔ ${C_GREEN}Cryptographic verification successful! Both keys are identical.${C_RESET}\n`);
  } else {
    console.log(`   ❌ ${C_RED}Cryptographic error: keys are not matching!${C_RESET}\n`);
    return;
  }


  console.log(`${C_BOLD}[Step 7] Verifier decrypts cipher text and validates GCM tag...${C_RESET}`);
  try {
    const decipher = crypto.createDecipheriv('aes-128-gcm', verifierAesKey, Buffer.from(recIvB64, 'base64url'));
    decipher.setAAD(Buffer.from(recHeaderB64, 'ascii'));
    decipher.setAuthTag(Buffer.from(recTagB64, 'base64url'));

    const decryptedBuffer = Buffer.concat([
      decipher.update(Buffer.from(recCiphertextB64, 'base64url')),
      decipher.final()
    ]);

    const decryptedClaims = JSON.parse(decryptedBuffer.toString('utf8'));
    console.log(`   ✔ ${C_GREEN}GCM integrity check successful.${C_RESET}`);
    console.log(`   ✔ ${C_GREEN}PID data decrypted successfully:${C_RESET}`);
    console.log(JSON.stringify(decryptedClaims, null, 2));

    console.log(`\n${C_BOLD}${C_GREEN}🎉 SUCCESS!${C_RESET}`);
  } catch (e) {
    console.error(`   ❌ ${C_RED}FAILURE: ${e.message}${C_RESET}`);
  }
}

// Start der Krypto-Demonstration
runDemo();
