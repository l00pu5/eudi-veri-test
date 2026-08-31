const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Colors for terminal output
const C_RESET = "\x1b[0m";
const C_BOLD = "\x1b[1m";
const C_GREEN = "\x1b[32m";
const C_BLUE = "\x1b[34m";
const C_YELLOW = "\x1b[33m";
const C_RED = "\x1b[31m";

function showHelp() {
  console.log(`
${C_BOLD}${C_BLUE}EUDI Wallet Crypto CLI Utility${C_RESET}
Usage:
  node eudi-crypto-tool.js <command> [options]

Commands:
  ${C_BOLD}gencert${C_RESET}       Genenrates a private EC keys pair and a self-signed
                X.509 certificate with SAN (Subject Alternative Name) for client.example.org
                Options:
                  --out-key=<path>  Default: ./rp-private-key.pem
                  --out-cert=<path> Default: ./rp-cert.pem

  ${C_BOLD}sign${C_RESET}          Generates a self-signed JWS document (e.g. JAR request object)
                Adds the certificate automatically to the x5c chain in the header
                Options:
                  --key=<path>      Path to the private EC key (PEM)
                  --cert=<path>     Path to the X.509 certificate(PEM) for the x5c header
                  --payload=<json>  Raw JSON string or path to a JSON file
                  --out=<path>      Output path for the signed JWS (default: stdout)

  ${C_BOLD}encrypt${C_RESET}       Encrypts a payload in JWE format (ECDH-ES + A128GCM).
                Options:
                  --pubkey=<path>   Path to public EC key of the receiver (PEM/JWK)
                  --payload=<str>   Payload string or path to a file
                  --out=<path>      Output path for the JWE token (default: stdout)

  ${C_BOLD}decrypt${C_RESET}       Decrypts a JWE compact token
                Options:
                  --key=<path>      Path to the private EC key of the receiver (PEM)
                  --jwe=<string>    JWE compact token string or path to a file

Examples:
  # 1. Generate key and certificate
  node eudi-crypto-tool.js gencert

  # 2. Sign JAR request object (JWS)
  node eudi-crypto-tool.js sign --key=rp-private-key.pem --cert=rp-cert.pem --payload='{"nonce":"123","client_id":"x509_san_dns:client.example.org"}'
    `);
}

// Helper: Parse CLI arguments
function parseArgs() {
  const args = process.argv.slice(3);
  const options = {};
  args.forEach(arg => {
    if (arg.startsWith('--')) {
      const parts = arg.slice(2).split('=');
      const key = parts[0];
      const val = parts.slice(1).join('=');
      options[key] = val;
    }
  });
  return options;
}

// Helper: Read payload (supports raw string or file path)
function getPayload(input) {
  if (!input) return null;
  try {
    if (fs.existsSync(input)) {
      return fs.readFileSync(input, 'utf8');
    }
  } catch (e) { }
  return input;
}

// COMMAND: gencert
function handleGenCert(options) {
  const keyPath = options['out-key'] || './rp-private-key.pem';
  const certPath = options['out-cert'] || './rp-cert.pem';

  console.log(`${C_BLUE}[gencert] Generatimg certificate chain for client.example.org...${C_RESET}`);
  try {
    const { execSync } = require('child_process');
    const cnfContent = `[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = client.example.org

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:client.example.org`;

    const cnfPath = path.join(path.dirname(keyPath), 'openssl-temp.cnf');
    fs.writeFileSync(cnfPath, cnfContent);

    execSync(`openssl ecparam -name prime256v1 -genkey -noout -out ${keyPath}`);
    execSync(`openssl req -new -x509 -key ${keyPath} -out ${certPath} -days 365 -config ${cnfPath}`);

    fs.unlinkSync(cnfPath);

    console.log(`${C_GREEN}✔ Key generated successfully:${C_RESET}`);
    console.log(`  Private key: ${C_BOLD}${keyPath}${C_RESET}`);
    console.log(`  Certificate:  ${C_BOLD}${certPath}${C_RESET}`);
  } catch (err) {
    console.error(`${C_RED}❌ Error during certificate generation via OpenSSL. Diverting to fallback...${C_RESET}`);
    // Fallback: Generate keys only (no self-signed cert since native Node can't easily write X.509 certs from scratch without forge)
    const { generateKeyPairSync } = crypto;
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    fs.writeFileSync(keyPath, privateKey.export({ type: 'sec1', format: 'pem' }));
    fs.writeFileSync(certPath, publicKey.export({ type: 'spki', format: 'pem' }));
    console.log(`${C_YELLOW}⚠️ Only key pair was generated (no X.509 certificate available due to OpenSSL error)${C_RESET}`);
  }
}

// COMMAND: sign (JWS with x5c)
function handleSign(options) {
  const keyPath = options['key'];
  const certPath = options['cert'];
  const payloadInput = options['payload'];
  const outPath = options['out'];

  if (!keyPath || !payloadInput) {
    console.error(`${C_RED}❌ Error: --key and --payload Are mandatory.${C_RESET}`);
    process.exit(1);
  }

  const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
  const privateKey = crypto.createPrivateKey(privateKeyPem);

  let certBase64 = null;
  if (certPath) {
    const certPem = fs.readFileSync(certPath, 'utf8');
    certBase64 = certPem
      .replace(/-----\s*(BEGIN|END)\s+CERTIFICATE\s*-----/g, '')
      .replace(/[\r\n]/g, '');
  }

  const payloadStr = getPayload(payloadInput);
  let payloadObj;
  try {
    payloadObj = JSON.parse(payloadStr);
  } catch (err) {
    console.error(`${C_RED}❌ Error: payload it not valid JSON.${C_RESET}`);
    process.exit(1);
  }

  // Sign JWS
  const header = {
    alg: 'ES256',
    typ: 'oauth-authz-req+jwt'
  };
  if (certBase64) {
    header.x5c = [certBase64];
  }

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');

  const signatureInput = `${headerB64}.${payloadB64}`;
  const signer = crypto.createSign('SHA256');
  signer.update(signatureInput);
  const signatureB64 = signer.sign(privateKey, 'base64url');

  const jwsCompact = `${signatureInput}.${signatureB64}`;

  if (outPath) {
    fs.writeFileSync(outPath, jwsCompact);
    console.log(`${C_GREEN}✔ JWS erfolgreich signiert und nach ${outPath} exportiert.${C_RESET}`);
  } else {
    console.log(`\n${C_BOLD}${C_GREEN}--- SIGNED JWS TOKEN (COMPACT) ---${C_RESET}`);
    console.log(jwsCompact);
  }
}

// Concat KDF implementation matching HAIP / RFC 7518
function deriveConcatKDF(sharedSecret, keyLenBytes, alg, apu, apv) {
  const roundOutputs = [];
  let counter = 1;
  const keyLenBits = keyLenBytes * 8;

  const algBuffer = Buffer.from(alg, 'ascii');
  const algLen = Buffer.alloc(4);
  algLen.writeUInt32BE(algBuffer.length, 0);
  const algorithmID = Buffer.concat([algLen, algBuffer]);

  const apuBuffer = apu ? Buffer.from(apu, 'base64url') : Buffer.alloc(0);
  const apuLen = Buffer.alloc(4);
  apuLen.writeUInt32BE(apuBuffer.length, 0);
  const partyUInfo = Buffer.concat([apuLen, apuBuffer]);

  const apvBuffer = apv ? Buffer.from(apv, 'base64url') : Buffer.alloc(0);
  const apvLen = Buffer.alloc(4);
  apvLen.writeUInt32BE(apvBuffer.length, 0);
  const partyVInfo = Buffer.concat([apvLen, apvBuffer]);

  const suppPubInfo = Buffer.alloc(4);
  suppPubInfo.writeUInt32BE(keyLenBits, 0);

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

// COMMAND: encrypt (JWE)
function handleEncrypt(options) {
  const pubKeyPath = options['pubkey'];
  const payloadInput = options['payload'];
  const outPath = options['out'];

  if (!pubKeyPath || !payloadInput) {
    console.error(`${C_RED}❌ Error: --pubkey and --payload are mandatory.${C_RESET}`);
    process.exit(1);
  }

  const payload = getPayload(payloadInput);
  const rawPubKey = fs.readFileSync(pubKeyPath, 'utf8');

  let recipientPubKey;
  try {
    if (rawPubKey.trim().startsWith('{')) {
      recipientPubKey = crypto.createPublicKey({ key: JSON.parse(rawPubKey), format: 'jwk' });
    } else {
      recipientPubKey = crypto.createPublicKey(rawPubKey);
    }
  } catch (e) {
    console.error(`${C_RED}❌ Error while reading the recipient public key:${C_RESET}`, e.message);
    process.exit(1);
  }

  // 1. generate ephemeral key pair for the sender
  const ephemeral = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const epkCnf = ephemeral.publicKey.export({ format: 'jwk' });

  // 2. calculate shared secret via ECDH
  const sharedSecret = crypto.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: recipientPubKey
  });

  // 3. Concat KDF for generating the AES-128 key (16 bytes)
  const derivedKey = deriveConcatKDF(sharedSecret, 16, 'A128GCM', null, null);

  // 4. symmetric AES-GCM encryption
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('A128GCM', derivedKey, iv);

  const jweHeader = {
    alg: 'ECDH-ES',
    enc: 'A128GCM',
    epk: {
      kty: 'EC',
      crv: 'P-256',
      x: epkCnf.x,
      y: epkCnf.y
    }
  };

  const protectedHeaderB64 = Buffer.from(JSON.stringify(jweHeader)).toString('base64url');
  cipher.setAAD(Buffer.from(protectedHeaderB64, 'ascii'));

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(payload, 'utf8')),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  const jweCompact = `${protectedHeaderB64}..${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${tag.toString('base64url')}`;

  if (outPath) {
    fs.writeFileSync(outPath, jweCompact);
    console.log(`${C_GREEN}✔ JWE encryption successfull and exported to ${outPath}${C_RESET}`);
  } else {
    console.log(`\n${C_BOLD}${C_GREEN}--- ENCRYPTED JWE TOKEN (ECDH-ES + AES-128-GCM) ---${C_RESET}`);
    console.log(jweCompact);
  }
}

// COMMAND: decrypt (JWE)
function handleDecrypt(options) {
  const keyPath = options['key'];
  const jweInput = options['jwe'];

  if (!keyPath || !jweInput) {
    console.error(`${C_RED}❌ Error: --key and --jwe are mandatory.${C_RESET}`);
    process.exit(1);
  }

  const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
  const privateKey = crypto.createPrivateKey(privateKeyPem);

  const jweString = getPayload(jweInput).trim();
  const parts = jweString.split('.');
  if (parts.length !== 5) {
    console.error(`${C_RED}❌ Error: invalid JWE compact format. 5 segments expected.${C_RESET}`);
    process.exit(1);
  }

  const [protectedHeaderB64, encryptedKeyB64, ivB64, ciphertextB64, tagB64] = parts;
  const header = JSON.parse(Buffer.from(protectedHeaderB64, 'base64url').toString('utf8'));

  if (header.alg !== 'ECDH-ES') {
    console.error(`${C_RED}❌ Error: unsupported JWE algorithm: ${header.alg}.${C_RESET}`);
    process.exit(1);
  }
  if (header.enc !== 'A128GCM') {
    console.error(`${C_RED}❌ Error: unsupported symmetric algorithm: ${header.enc}.${C_RESET}`);
    process.exit(1);
  }

  const walletEphemeralPublicKey = crypto.createPublicKey({
    key: header.epk,
    format: 'jwk'
  });

  // 1. calculate shared secret via ECDH
  const sharedSecret = crypto.diffieHellman({
    privateKey: privateKey,
    publicKey: walletEphemeralPublicKey
  });

  // 2. Concat KDF
  const derivedKey = deriveConcatKDF(sharedSecret, 16, 'A128GCM', null, null);

  // 3. symmetric decryption
  const iv = Buffer.from(ivB64, 'base64url');
  const ciphertext = Buffer.from(ciphertextB64, 'base64url');
  const tag = Buffer.from(tagB64, 'base64url');

  const decipher = crypto.createDecipheriv('A128GCM', derivedKey, iv);
  decipher.setAuthTag(tag);
  decipher.setAAD(Buffer.from(protectedHeaderB64, 'ascii'));

  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]).toString('utf8');

    console.log(`\n${C_BOLD}${C_GREEN}--- DECRYPTED PAYLOAD DATA ---${C_RESET}`);
    try {
      // Pretty-print JSON if possible
      console.log(JSON.stringify(JSON.parse(decrypted), null, 2));
    } catch (e) {
      console.log(decrypted);
    }
  } catch (err) {
    console.error(`${C_RED}❌ Error while decrypting or integrity check (tag mismatch).${C_RESET}`);
    process.exit(1);
  }
}

// CLI Dispatcher
const command = process.argv[2];
const options = parseArgs();

switch (command) {
  case 'gencert':
    handleGenCert(options);
    break;
  case 'sign':
    handleSign(options);
    break;
  case 'encrypt':
    handleEncrypt(options);
    break;
  case 'decrypt':
    handleDecrypt(options);
    break;
  default:
    showHelp();
    break;
}
