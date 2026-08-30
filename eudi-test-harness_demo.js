/**
 * EUDI Wallet - Test Harness & end-to-end Integration Simulator
 * 
 * This script simulates the presentation & issuance flows.
 * 
 * Supported simulation modes (can be defined via argument --mode):
 *   --mode=1 (simple):    Unencrypted direct_post presetation (Erika Mustermann SD-JWT VC mock)
 *   --mode=2 (encrypted): Encrypted direct_post.jwt presentation via JWE (ECDH-ES + AES-128-GCM)
 *   --mode=3 (e2e):       End-to-end test: dynamic issuance (OpenID4VCI) + encrypted presentation (OpenID4VP) of a SD-JWT PID
 *   --mode=4 (mdoc):      CBOR- and mdoc-based mDL presentation with SessionTranscript and binary DeviceResponse CBOR simulation
 *   --mode=5 (mdoc e2e):  mDL end-to-end test (mDL issuance + mdoc presentation) 
 * 
 * Ausführung:
 *   node eudi-test-harness_demo.js --mode=4
 */

const crypto = require('crypto');
const fs = require('fs');

const API_BASE = 'http://localhost:3000';

// ANSCI escape codes for colored terminal output
const COLOR_RESET = '\x1b[0m';
const COLOR_INFO = '\x1b[34m';
const COLOR_SUCCESS = '\x1b[32m';
const COLOR_WARN = '\x1b[33m';
const COLOR_ERROR = '\x1b[31m';
const COLOR_CYAN = '\x1b[36m';
const COLOR_BOLD = '\x1b[1m';

// ─────────────────────────────────────────────────────────────────────────────
// LIGHTWEIGHT CBOR CODEC (RFC 8949)
// ─────────────────────────────────────────────────────────────────────────────

function encodeTypeAndLength(type, length) {
  const major = type << 5;
  if (length < 24) {
    return Buffer.from([major | length]);
  } else if (length < 0x100) {
    return Buffer.from([major | 24, length]);
  } else if (length < 0x10000) {
    const buf = Buffer.alloc(3);
    buf[0] = major | 25;
    buf.writeUInt16BE(length, 1);
    return buf;
  } else {
    const buf = Buffer.alloc(5);
    buf[0] = major | 26;
    buf.writeUInt32BE(length, 1);
    return buf;
  }
}

function encodeCBOR(val) {
  if (val === null) {
    return Buffer.from([0xf6]);
  }
  if (val === undefined) {
    return Buffer.from([0xf7]);
  }
  if (typeof val === 'boolean') {
    return Buffer.from([val ? 0xf5 : 0xf4]);
  }
  if (typeof val === 'number') {
    if (Number.isInteger(val)) {
      if (val >= 0) {
        return encodeTypeAndLength(0, val);
      } else {
        return encodeTypeAndLength(1, -val - 1);
      }
    } else {
      throw new Error("Floating point numbers not supported on this layer.");
    }
  }
  if (typeof val === 'string') {
    const buf = Buffer.from(val, 'utf8');
    return Buffer.concat([encodeTypeAndLength(3, buf.length), buf]);
  }
  if (Buffer.isBuffer(val)) {
    return Buffer.concat([encodeTypeAndLength(2, val.length), val]);
  }
  if (Array.isArray(val)) {
    const encodedElements = val.map(encodeCBOR);
    return Buffer.concat([encodeTypeAndLength(4, val.length), ...encodedElements]);
  }
  if (typeof val === 'object') {
    const keys = Object.keys(val);
    const encodedPairs = [];
    for (const k of keys) {
      encodedPairs.push(encodeCBOR(k));
      encodedPairs.push(encodeCBOR(val[k]));
    }
    return Buffer.concat([encodeTypeAndLength(5, keys.length), ...encodedPairs]);
  }
  throw new Error("Unsupported CBOR data type:" + typeof val);
}

// aux function for base64url encoding
function base64url(strOrBuffer) {
  const buffer = Buffer.isBuffer(strOrBuffer) ? strOrBuffer : Buffer.from(strOrBuffer);
  return buffer.toString('base64url');
}

// aux function for JWK thumbprint (RFC 7638)
function getJwkThumbprint(jwk) {
  const sortedJwk = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  };
  const jwkString = JSON.stringify(sortedJwk);
  return crypto.createHash('sha256').update(jwkString).digest();
}

// aux function for JWS token signing (native ES256)
function signJws(header, payload, privateKey) {
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const dataToSign = `${headerB64}.${payloadB64}`;

  const signer = crypto.createSign('SHA256');
  signer.update(dataToSign);
  const signature = signer.sign(privateKey, 'base64url');

  return `${dataToSign}.${signature}`;
}

/**
 * Concat KDF acc. RFC 7518 for CEK derivation (AES-128-GCM)
 */
function deriveConcatKDF(sharedSecret, keyLenBytes, alg, apu, apv) {
  const roundOutputs = [];
  let counter = 1;
  const keyLenBits = keyLenBytes * 8;

  // AlgorithmID: 32-bit length prefix + alg string bytes
  const algBuffer = Buffer.from(alg, 'ascii');
  const algLen = Buffer.alloc(4);
  algLen.writeUInt32BE(algBuffer.length, 0);
  const algorithmID = Buffer.concat([algLen, algBuffer]);

  // PartyUInfo: 32-bit length prefix + apu bytes (if present, else empty)
  const apuBuffer = apu ? Buffer.from(apu, 'base64url') : Buffer.alloc(0);
  const apuLen = Buffer.alloc(4);
  apuLen.writeUInt32BE(apuBuffer.length, 0);
  const partyUInfo = Buffer.concat([apuLen, apuBuffer]);

  // PartyVInfo: 32-bit length prefix + apv bytes (if present, else empty)
  const apvBuffer = apv ? Buffer.from(apv, 'base64url') : Buffer.alloc(0);
  const apvLen = Buffer.alloc(4);
  apvLen.writeUInt32BE(apvBuffer.length, 0);
  const partyVInfo = Buffer.concat([apvLen, apvBuffer]);

  // SuppPubInfo: 32-bit big-endian integer representing key length in bits
  const suppPubInfo = Buffer.alloc(4);
  suppPubInfo.writeUInt32BE(keyLenBits, 0);

  // Concat all to form fixedInfo (OtherInfo)
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

// time measurement data structure
const rTimes = {};
function trackTime(label, fnOrPromise) {
  const start = process.hrtime.bigint();
  if (fnOrPromise instanceof Promise) {
    return fnOrPromise.then(res => {
      const end = process.hrtime.bigint();
      rTimes[label] = Number(end - start) / 1_000_000; // ms
      return res;
    });
  } else {
    const res = fnOrPromise();
    const end = process.hrtime.bigint();
    rTimes[label] = Number(end - start) / 1_000_000;
    return res;
  }
}

async function run() {
  const args = process.argv.slice(2);
  let modeArg = args.find(arg => arg.startsWith('--mode='));
  let mode = modeArg ? modeArg.split('=')[1] : '3'; // default: mode 3 (E2E)

  let sidArg = args.find(arg => arg.startsWith('--sid='));
  let externalSid = sidArg ? sidArg.split('=')[1] : null;

  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`${COLOR_BOLD}${COLOR_INFO}📱 EUDI WALLET - UNIFIED CRYPTO-TEST HARNESS & CLIENT (JS)${COLOR_RESET}`);
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`Selected simulation mode: ${COLOR_BOLD}${COLOR_WARN}Modus ${mode}${COLOR_RESET}`);
  if (externalSid) {
    console.log(`Browser session ID coupled: ${COLOR_BOLD}${COLOR_SUCCESS}${externalSid}${COLOR_RESET}`);
  }

  if (mode === '1') {
    console.log(`Description: Unencrypted direct_post presentation (mock claims).`);
    await runPresentation(false, null, externalSid);
  } else if (mode === '2') {
    console.log(`Description: Encrypted direct_post.jwt presentation (JWE via ECDH-ES).`);
    await runPresentation(true, null, externalSid);
  } else if (mode === '3') {
    console.log(`Description: end-to-end flow (issuance + JWE presentation).`);
    const issuedCredential = await runIssuance('dc+sd-jwt', externalSid);
    if (externalSid && externalSid.startsWith('session_iss_')) {
      console.log(`🎉 Successful! PID has been issued to browser session.`);
    } else {
      await runPresentation(true, issuedCredential, externalSid);
    }
  } else if (mode === '4') {
    console.log(`Description: mdoc presentation (mDL) with binary DeviceResponse CBOR simulation.`);
    await runMdocPresentation(true, externalSid); // mdoc mit JWE verschlüsselt senden
  } else if (mode === '5') {
    console.log(`Description: end-to-end mDL flow (mDL issuance + mdoc presentation).`);
    const issuedCredential = await runIssuance('mso_mdoc', externalSid);
    if (externalSid && externalSid.startsWith('session_iss_')) {
      console.log(`🎉 Successful! mDL has been issued to browser session.`);
    } else {
      await runMdocPresentation(true, externalSid, issuedCredential);
    }
  } else {
    console.error(`${COLOR_ERROR}❌ Invalid mode: ${mode}. Supported modes: 1, 2, 3, 4, 5.${COLOR_RESET}`);
    process.exit(1);
  }

  printStatsTable();
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * STEP A: ISSUANCE PROCESS (OpenID4VCI) - mode 3
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function runIssuance(format = 'dc+sd-jwt', externalSid = null) {
  console.log(`\n${COLOR_INFO}--- PHASE 1: DYNAMIC PID ISSUANCE (OpenID4VCI) ---${COLOR_RESET}`);
  console.log(` Format: ${COLOR_BOLD}${format}${COLOR_RESET}`);

  const keysPath = './demo-keys.json';
  if (!fs.existsSync(keysPath)) {
    console.error(`${COLOR_ERROR}❌ Error: no active demo keys found!${COLOR_RESET}`);
    console.error(`Please ensure that the backend service is started via:`);
    console.error(` node eudi-verifier-server-v9.js`);
    process.exit(1);
  }

  console.log(`[VCI 1] Loadinh PKI keys of the wallet provider...`);
  const demoKeys = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  console.log(` ✔ Keys loaded successfully.`);

  console.log(`[VCI 2] Generating ephemeral wallet and device binding keys (P-256)...`);
  const walletKeyPair = trackTime('Key generation: Wallet (P-256)', () =>
    crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  );
  const deviceKeyPair = trackTime('Key generation: Device-Binding (P-256)', () =>
    crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  );
  const walletPubKeyJwk = walletKeyPair.publicKey.export({ format: 'jwk' });
  const devicePubKeyJwk = deviceKeyPair.publicKey.export({ format: 'jwk' });

  let sessionId, wiaChallenge;
  if (externalSid && externalSid.startsWith('session_iss_')) {
    console.log(`[VCI 3] Using browser issuance session: ${externalSid}`);
    sessionId = externalSid;
    const sessionInfo = await trackTime('HTTP: fetching VCI session info',
      fetch(`${API_BASE}/api/issuance/session-info?sid=${sessionId}`).then(res => res.json())
    );
    wiaChallenge = sessionInfo.wiaChallenge;
    console.log(` ✔ Challenge retrieved successfully: ${wiaChallenge}`);
  } else {
    console.log(`[VCI 3] Initiating new issuance session...`);
    const initResponse = await trackTime('HTTP: initiating VCI session',
      fetch(`${API_BASE}/api/issuance/initiate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: format })
      }).then(res => res.json())
    );
    sessionId = initResponse.sessionId;
    wiaChallenge = initResponse.wiaChallenge;
  }
  console.log(` ✔ Session created. ID: ${sessionId}`);

  console.log(`[VCI 4] Hole frische Einmal-Nonces vom Nonce-Endpoint...`);
  const nonceResponse = await trackTime('HTTP: Hole VCI Nonces',
    fetch(`${API_BASE}/api/issuance/nonce`, { method: 'POST' }).then(res => res.json())
  );

  console.log(`[VCI 5] Preparing WIA & WIA PoP...`);
  const wiaToken = trackTime('Crypto: Signing WIA JWT', () => {
    const header = { alg: 'ES256', typ: 'oauth-client-attestation+jwt' };
    const payload = {
      iss: 'https://wallet-provider.de',
      sub: 'https://wallet.example.com/instances/12345',
      cnf: { jwk: walletPubKeyJwk }
    };
    return signJws(header, payload, demoKeys.demoWalletKeys.privateKey);
  });

  const wiaPop = trackTime('Crypto: Signing WIA PoP JWT', () => {
    const header = { alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' };
    const payload = {
      iss: 'https://wallet-provider.de',
      aud: `${API_BASE}/api/issuance`,
      challenge: wiaChallenge
    };
    return signJws(header, payload, walletKeyPair.privateKey);
  });

  console.log(`[VCI 6] Generating DPoP proof for token endpoint (sender constrainting)...`);
  const tokenDpopProof = trackTime('Crypto: Signing Token DPoP Proof', () => {
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletPubKeyJwk };
    const payload = {
      htm: 'POST',
      htu: `${API_BASE}/api/issuance/token`,
      nonce: nonceResponse.dpop_nonce
    };
    return signJws(header, payload, walletKeyPair.privateKey);
  });

  console.log(`[VCI 7] Sending token exchange request...`);
  const tokenRequestBody = {
    code: 'dummy_auth_code_123',
    code_verifier: 'dummy_code_verifier_123',
    client_assertion: wiaToken,
    client_assertion_pop: wiaPop,
    wia_challenge_sid: sessionId
  };

  const tokenResponse = await trackTime('HTTP: Token Exchange (/token)',
    fetch(`${API_BASE}/api/issuance/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'DPoP': tokenDpopProof
      },
      body: JSON.stringify(tokenRequestBody)
    }).then(res => res.json())
  );

  console.log(`[VCI 8] Preparing PoP (Device-Binding Proof) vor...`);
  const credNonces = await trackTime('HTTP: fetching VCI crendential nonces',
    fetch(`${API_BASE}/api/issuance/nonce`, { method: 'POST' }).then(res => res.json())
  );

  const credDpopProof = trackTime('Crypto: Signing credential DPoP proof', () => {
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletPubKeyJwk };
    const payload = {
      htm: 'POST',
      htu: `${API_BASE}/api/issuance/credential`,
      nonce: credNonces.dpop_nonce
    };
    return signJws(header, payload, walletKeyPair.privateKey);
  });

  const popProofJwt = trackTime('Crypto: Signing Device-Binding PoP (c_nonce)', () => {
    const header = { alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: devicePubKeyJwk };
    const payload = {
      aud: `${API_BASE}/api/issuance`,
      nonce: credNonces.c_nonce
    };
    return signJws(header, payload, deviceKeyPair.privateKey);
  });

  console.log(`[VCI 9] Retrieving mdoc/SD-JWT PID...`);
  const credRequestPayload = {
    credential_configuration_id: format === 'mso_mdoc' ? 'mDL_mso_mdoc' : 'PID_SD_JWT_VC',
    proofs: {
      jwt: popProofJwt
    }
  };

  const credResponse = await trackTime('HTTP: fetching PID (/credential)',
    fetch(`${API_BASE}/api/issuance/credential`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `DPoP ${tokenResponse.access_token}`,
        'DPoP': credDpopProof
      },
      body: JSON.stringify(credRequestPayload)
    }).then(res => res.json())
  );

  const issuedCredential = credResponse.credentials[0].credential;
  console.log(`${COLOR_SUCCESS}✅ PID issued successfully! (length: ${issuedCredential.length} chars)${COLOR_RESET}`);

  return {
    credential: issuedCredential,
    devicePrivateKey: deviceKeyPair.privateKey,
    devicePubKeyJwk: devicePubKeyJwk
  };
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * STEP B: PRESENTATION (OpenID4VP) - modes 1, 2 and 3
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function runPresentation(useEncryption, issuedData, externalSid = null) {
  console.log(`\n${COLOR_INFO}--- PHASE 2: PID PRESENTATION (OpenID4VP) ---${COLOR_RESET}`);

  let sessionId, requestUri;
  if (externalSid) {
    console.log(`[VP 1] Using browser session ID: ${externalSid}`);
    sessionId = externalSid;
    requestUri = `${API_BASE}/api/presentation/request-jwt?sid=${sessionId}`;
  } else {
    console.log(`[VP 1] Initating new presentation session at the verifier...`);
    const initResponse = await trackTime('HTTP: Initiating VP session',
      fetch(`${API_BASE}/api/presentation/initiate`).then(res => res.json())
    );
    sessionId = initResponse.sessionId;
    const qrCodeUrl = initResponse.qrCodeUrl;
    console.log(` ✔ Session created successfully. ID: ${sessionId}`);
    requestUri = new URL(qrCodeUrl).searchParams.get('request_uri');
  }

  console.log(`[VP 2] fetching request object (JAR) via request_uri...`);
  const signedJar = await trackTime('HTTP: Fetching JAR request',
    fetch(requestUri).then(res => res.text())
  );

  const jarPayloadB64 = signedJar.split('.')[1];
  const jarPayload = JSON.parse(Buffer.from(jarPayloadB64, 'base64url').toString('utf8'));
  const nonce = jarPayload.nonce;
  const rpKeyJwk = jarPayload.client_metadata?.jwks?.keys[0];

  console.log(` ✔ JAR retrieved and demasked successfully.`);
  console.log(` ✔ Extracted presentation nonce: ${nonce}`);

  console.log(`[VP 3] Preparing presentation payload (SD-JWT VC + Key Binding)...`);
  let finalSdJwt;
  let presentationDevicePrivateKey;

  if (issuedData) {
    console.log(` 👉 Using dynamically generated PID.`);
    const issuedCredential = issuedData.credential;
    presentationDevicePrivateKey = issuedData.devicePrivateKey;

    const parts = issuedCredential.split('~');
    const issuerJwt = parts[0];
    const disclosures = parts.slice(1, -1);

    const kbHeader = { alg: 'ES256', typ: 'kb+jwt' };
    const kbPayload = {
      nonce: nonce,
      aud: "x509_san_dns:client.example.org",
      iat: Math.floor(Date.now() / 1000),
      sd_hash: "Dy-RYwZfaaoC3inJbLslgPvMp09bH-clYP_3qbRqtW4"
    };

    const kbJwt = trackTime('Crypto: signing key binding (KB-JWT)', () =>
      signJws(kbHeader, kbPayload, presentationDevicePrivateKey)
    );

    finalSdJwt = `${issuerJwt}~${disclosures.join('~')}~${kbJwt}`;
  } else {
    console.log(` 👉 Using statically signed mock PID for Erika Mustermann.`);
    const mockDeviceKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    presentationDevicePrivateKey = mockDeviceKeyPair.privateKey;

    const ISSUER_HEADER_B64 = Buffer.from(JSON.stringify({ alg: "ES256", typ: "dc+sd-jwt" })).toString('base64url');
    const ISSUER_PAYLOAD_B64 = Buffer.from(JSON.stringify({
      iss: "https://registry.government.de/pid-issuer",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      vct: "https://credentials.example.com/identity_credential",
      _sd_alg: "sha-256",
      _sd: [
        "0md4eSFDWig7Gad1CZiRy1I4gcG4fKOmzGNEmOdABiI",
        "ZmgxyNRwqRHzYCllHNESq_NuKQJ7GvmDtXJA9OhKJbA",
        "cZ4ca70cY9cYxbIf9x4GUsrcxGWT11xmeF5AA_tDD7M",
        "QeMxEMSmDeM3jvVxU5b2bMAFASh1IHxKTitvmu7zhbc",
        "I-TdVkhTXvk1nRhzJrWgwGXp5wjkLxPjISAZ_2sCwG4"
      ],
      cnf: { jwk: { kty: "EC", crv: "P-256", x: "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc", y: "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ" } }
    })).toString('base64url');
    const mockIssuerSig = "simulated_government_issuer_signature";
    const issuerJwt = `${ISSUER_HEADER_B64}.${ISSUER_PAYLOAD_B64}.${mockIssuerSig}`;

    const DISCLOSURE_1 = Buffer.from(JSON.stringify(["2GLC42sKQveCfGfryNRN9w", "given_name", "Erika"])).toString('base64url');
    const DISCLOSURE_2 = Buffer.from(JSON.stringify(["eluV5Og3gSNII8EYnsxA_A", "family_name", "Mustermann"])).toString('base64url');
    const DISCLOSURE_3 = Buffer.from(JSON.stringify(["6Ij7tM-a5iVPGboS5tmvVA", "birthdate", "1998-08-12"])).toString('base64url');
    const DISCLOSURE_4 = Buffer.from(JSON.stringify(["Pc33JM2LchcU_lHggv_ufQ", "is_over_18", true])).toString('base64url');
    const DISCLOSURE_5 = Buffer.from(JSON.stringify(["Qg_O64zqAxe412a108iroA", "address", { street_address: "Heidestraße 17", locality: "Köln", postal_code: "50667", country: "DE" }])).toString('base64url');

    const KB_HEADER_B64 = Buffer.from(JSON.stringify({ alg: "ES256", typ: "kb+jwt" })).toString('base64url');
    const KB_PAYLOAD_B64 = Buffer.from(JSON.stringify({
      nonce: nonce,
      aud: "x509_san_dns:client.example.org",
      iat: Math.floor(Date.now() / 1000),
      sd_hash: "Dy-RYwZfaaoC3inJbLslgPvMp09bH-clYP_3qbRqtW4"
    })).toString('base64url');
    const mockDeviceSig = "simulated_device_secure_element_signature";
    const kbJwt = `${KB_HEADER_B64}.${KB_PAYLOAD_B64}.${mockDeviceSig}`;

    finalSdJwt = `${issuerJwt}~${DISCLOSURE_1}~${DISCLOSURE_2}~${DISCLOSURE_3}~${DISCLOSURE_4}~${DISCLOSURE_5}~${kbJwt}`;
  }

  const cleartextPayload = {
    vp_token: {
      my_identity_credential: [finalSdJwt]
    },
    wia_token: `eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.${Buffer.from(JSON.stringify({
      iss: "https://wallet-provider-backend.eudi-wallet.de",
      sub: "https://wallet.example.com/instances/12345",
      wallet_name: "EUDI National Reference Wallet",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    })).toString('base64url')}.simulated_wallet_manufacturer_signature`
  };

  let postBodyString;
  let postContentType = 'application/x-www-form-urlencoded';

  if (useEncryption && rpKeyJwk) {
    console.log(`[VP 4] Encrypting presentation via JWE (ECDH-ES + AES-128-GCM)...`);

    const walletEncKeyPair = trackTime('Key generation: ephemeral VP key (P-256)', () =>
      crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    );
    const walletEncPubKeyJwk = walletEncKeyPair.publicKey.export({ format: 'jwk' });

    const rpPublicKey = crypto.createPublicKey({ key: rpKeyJwk, format: 'jwk' });
    const sharedSecret = trackTime('Crypto: ECDH key agreement', () =>
      crypto.diffieHellman({
        privateKey: walletEncKeyPair.privateKey,
        publicKey: rpPublicKey
      })
    );

    const cek = trackTime('Crypto: Concat KDF key derivation', () =>
      deriveConcatKDF(sharedSecret, 16, 'A128GCM')
    );

    const jweString = trackTime('Crypto: AES-128-GCM JWE encryption', () => {
      const jweHeader = {
        alg: 'ECDH-ES',
        enc: 'A128GCM',
        epk: walletEncPubKeyJwk
      };
      const headerB64 = Buffer.from(JSON.stringify(jweHeader)).toString('base64url');
      const iv = crypto.randomBytes(12);

      const cipher = crypto.createCipheriv('aes-128-gcm', cek, iv);
      cipher.setAAD(Buffer.from(headerB64, 'ascii'));

      const ciphertext = Buffer.concat([
        cipher.update(Buffer.from(JSON.stringify(cleartextPayload))),
        cipher.final()
      ]);
      const tag = cipher.getAuthTag();

      return `${headerB64}..${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${tag.toString('base64url')}`;
    });

    console.log(` ✔ JWE encryption completed. JWE: ${jweString.substring(0, 50)}...`);
    postBodyString = `response=${encodeURIComponent(jweString)}&state=${encodeURIComponent(sessionId)}`;
  } else {
    console.log(`[VP 4] Sending unencrypted payload (fallback: direct_post)...`);
    postBodyString = `vp_token=${encodeURIComponent(JSON.stringify(cleartextPayload.vp_token))}&wia_token=${encodeURIComponent(cleartextPayload.wia_token)}&state=${encodeURIComponent(sessionId)}`;
  }

  console.log(`[VP 5] Transmitting direct_post callback to RP server...`);
  const callbackResponse = await trackTime('HTTP: direct_post callback transmission',
    fetch(`${API_BASE}/api/presentation/callback`, {
      method: 'POST',
      headers: { 'Content-Type': postContentType },
      body: postBodyString
    }).then(res => res.json())
  );
  console.log(` ✔ Server returns redirect URI: ${callbackResponse.redirect_uri}`);

  console.log(`[VP 6] Fetching final verification status from server...`);
  const statusResponse = await trackTime('HTTP: Polling Onboarding Status',
    fetch(`${API_BASE}/api/presentation/status?sid=${sessionId}`).then(res => res.json())
  );

  console.log(`\n${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`${COLOR_BOLD}${COLOR_SUCCESS}🎯 STATUS OF PRESENTATION VERIFICATION: ${statusResponse.status}${COLOR_RESET}`);
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`Transport encryption (JWE): ${COLOR_BOLD}${statusResponse.isEncrypted ? 'YES 🔒 (direct_post.jwt)' : 'NO ⚠️ (direct_post)'}${COLOR_RESET}`);
  console.log(`Transmitted claims:`);
  console.log(JSON.stringify(statusResponse.claims, null, 2));
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}\n`);
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * STEP C: MDOC PRESENTATION (MODE 4)
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function runMdocPresentation(useEncryption, externalSid = null, issuedData = null) {
  console.log(`\n${COLOR_INFO}--- PID PRESENTATION IN ISO MDOC FORMAT (mDL) ---${COLOR_RESET}`);

  let sessionId, requestUri;
  if (externalSid) {
    console.log(`[mdoc 1] Using browser session ID: ${externalSid}`);
    sessionId = externalSid;
    requestUri = `${API_BASE}/api/presentation/request-jwt?sid=${sessionId}`;
  } else {
    console.log(`[mdoc 1] Initiating new presentation session at the verifier...`);
    const initResponse = await trackTime('HTTP: Initiating mdoc session',
      fetch(`${API_BASE}/api/presentation/initiate`).then(res => res.json())
    );
    sessionId = initResponse.sessionId;
    const qrCodeUrl = initResponse.qrCodeUrl;
    console.log(` ✔ Session created successfully. ID: ${sessionId}`);
    requestUri = new URL(qrCodeUrl).searchParams.get('request_uri');
  }

  console.log(`[mdoc 2] Fetching request object (JAR) via request_uri...`);
  const signedJar = await trackTime('HTTP: Fetching JAR request',
    fetch(requestUri).then(res => res.text())
  );

  const jarPayloadB64 = signedJar.split('.')[1];
  const jarPayload = JSON.parse(Buffer.from(jarPayloadB64, 'base64url').toString('utf8'));
  const nonce = jarPayload.nonce;
  const rpKeyJwk = jarPayload.client_metadata?.jwks?.keys[0];

  console.log(` ✔ Extracted presentation nonce: ${nonce}`);

  console.log(`[mdoc 3] Generating SesseionTranscript (ISO 18013-5)...`);

  // 1. Building HandoverInfo structure aufbauen + CBOR encoding
  const rpClientId = "x509_san_dns:client.example.org";
  const responseUri = `${API_BASE}/api/presentation/callback`;

  let jwkThumbprint = null;
  if (useEncryption && rpKeyJwk) {
    jwkThumbprint = trackTime('Crypto: Calculating JWK thumbprint (RFC 7638)', () => getJwkThumbprint(rpKeyJwk));
  }

  const handoverInfo = [
    rpClientId,
    nonce,
    jwkThumbprint,
    responseUri
  ];

  const handoverInfoCbor = encodeCBOR(handoverInfo);
  const handoverInfoHash = crypto.createHash('sha256').update(handoverInfoCbor).digest();

  const handover = [
    "OpenID4VPHandover",
    handoverInfoHash
  ];

  const sessionTranscript = [
    null, // DeviceEngagementBytes
    null, // EReaderKeyBytes
    handover
  ];

  const sessionTranscriptCbor = trackTime('CBOR: encoding SessionTranscript', () => encodeCBOR(sessionTranscript));
  console.log(` ✔ SessionTranscript CBOR encoding complete (${sessionTranscriptCbor.length} bytes).`);

  // 2. generating Erika Mustermann mdoc DeviceResponse CBOR document
  console.log(`[mdoc 4] Genrating mdoc document and signing device binding...`);

  const mdNameSpace = {
    "org.iso.18013.5.1": {
      given_name: "Erika",
      family_name: "Mustermann",
      birth_date: "1998-08-12",
      issue_date: "2026-08-20",
      expiry_date: "2036-08-20",
      issuing_country: "DE",
      driving_privileges: "B"
    }
  };

  const document = {
    docType: "org.iso.18013.5.1.mDL",
    issuerSigned: {
      nameSpaces: mdNameSpace,
      issuerAuth: encodeCBOR({
        protected: Buffer.from("issuer_protected_headers"),
        unprotected: {},
        payload: Buffer.from("issuer_signed_mdl_payload"),
        signature: Buffer.from("simulated_government_issuer_signature")
      })
    },
    deviceSigned: {
      nameSpaces: {},
      deviceAuth: {
        deviceSignature: {
          protected: Buffer.from("device_protected_headers"),
          unprotected: {},
          payload: null,
          signature: Buffer.from("simulated_device_secure_element_signature")
        }
      }
    }
  };

  const deviceResponse = {
    version: "1.0",
    documents: [document],
    status: 0
  };

  const deviceResponseCbor = encodeCBOR(deviceResponse);
  const base64DeviceResponse = base64url(deviceResponseCbor);

  // building callback payload
  const finalMdlBase64 = issuedData ? issuedData.credential : base64DeviceResponse;
  const cleartextPayload = {
    vp_token: {
      my_mdl_credential: [finalMdlBase64]
    },
    wia_token: `eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.${base64url(JSON.stringify({
      iss: "https://wallet-provider-backend.eudi-wallet.de",
      sub: "https://wallet.example.com/instances/12345",
      wallet_name: "EUDI National Reference Wallet",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    }))}.simulated_wallet_manufacturer_signature`
  };

  let postBodyString;
  let postContentType = 'application/x-www-form-urlencoded';

  if (useEncryption && rpKeyJwk) {
    console.log(`[mdoc 5] Encrypting mdoc via JWE (ECDH-ES + AES-128-GCM)...`);

    const walletEncKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const walletEncPubKeyJwk = walletEncKeyPair.publicKey.export({ format: 'jwk' });

    const rpPublicKey = crypto.createPublicKey({ key: rpKeyJwk, format: 'jwk' });
    const sharedSecret = crypto.diffieHellman({
      privateKey: walletEncKeyPair.privateKey,
      publicKey: rpPublicKey
    });

    const cek = deriveConcatKDF(sharedSecret, 16, 'A128GCM');

    const jweString = trackTime('Crypto: AES-128-GCM JWE encryption', () => {
      const jweHeader = {
        alg: 'ECDH-ES',
        enc: 'A128GCM',
        epk: walletEncPubKeyJwk
      };
      const headerB64 = Buffer.from(JSON.stringify(jweHeader)).toString('base64url');
      const iv = crypto.randomBytes(12);

      const cipher = crypto.createCipheriv('aes-128-gcm', cek, iv);
      cipher.setAAD(Buffer.from(headerB64, 'ascii'));

      const ciphertext = Buffer.concat([
        cipher.update(Buffer.from(JSON.stringify(cleartextPayload))),
        cipher.final()
      ]);
      const tag = cipher.getAuthTag();

      return `${headerB64}..${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${tag.toString('base64url')}`;
    });

    postBodyString = `response=${encodeURIComponent(jweString)}&state=${encodeURIComponent(sessionId)}`;
  } else {
    postBodyString = `vp_token=${encodeURIComponent(JSON.stringify(cleartextPayload.vp_token))}&wia_token=${encodeURIComponent(cleartextPayload.wia_token)}&state=${encodeURIComponent(sessionId)}`;
  }

  console.log(`[mdoc 6] Transmitting direct_post.jwt callback to RP server...`);
  const callbackResponse = await trackTime('HTTP: direct_post Callback übermitteln',
    fetch(`${API_BASE}/api/presentation/callback`, {
      method: 'POST',
      headers: { 'Content-Type': postContentType },
      body: postBodyString
    }).then(res => res.json())
  );
  console.log(` ✔ Server returns redirect URI: ${callbackResponse.redirect_uri}`);

  console.log(`[mdoc 7] Requesting final verification status from server...`);
  const statusResponse = await trackTime('HTTP: Polling Onboarding Status',
    fetch(`${API_BASE}/api/presentation/status?sid=${sessionId}`).then(res => res.json())
  );

  console.log(`\n${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`${COLOR_BOLD}${COLOR_SUCCESS}🎯 STATUS OF PRESENTATION VERIFICATION: ${statusResponse.status}${COLOR_RESET}`);
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`Presented format:             ${COLOR_BOLD}ISO mdoc (mDL)${COLOR_RESET}`);
  console.log(`Transport encryption (JWE):  ${COLOR_BOLD}${statusResponse.isEncrypted ? 'YES 🔒 (direct_post.jwt)' : 'NO ⚠️ (direct_post)'}${COLOR_RESET}`);
  console.log(`Transmitted mDL claims:`);
  console.log(JSON.stringify(statusResponse.claims, null, 2));
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}\n`);
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * PRINT STATS TABLE (performance benchamrking)
 * ─────────────────────────────────────────────────────────────────────────────
 */
function printStatsTable() {
  console.log(`${COLOR_BOLD}${COLOR_CYAN}📊 CONSOLIDATED TRANSACTION RUNTIME STATISTIC${COLOR_RESET}`);

  const col1Width = 55;
  const col2Width = 14;

  console.log(`+-${'-'.repeat(col1Width)}-+-${'-'.repeat(col2Width)}-+`);
  console.log(`| ${COLOR_BOLD}${'Action / Step'.padEnd(col1Width)}${COLOR_RESET} | ${COLOR_BOLD}${'Laufzeit'.padEnd(col2Width)}${COLOR_RESET} |`);
  console.log(`+-${'-'.repeat(col1Width)}-+-${'-'.repeat(col2Width)}-+`);

  let totalTime = 0;
  for (const [label, time] of Object.entries(rTimes)) {
    const padding = ' '.repeat(Math.max(0, col1Width - label.length));
    const timeStr = time.toFixed(2) + " ms";
    const timePadding = ' '.repeat(Math.max(0, col2Width - timeStr.length));
    console.log(`| ${label}${padding} | ${COLOR_BOLD}${timeStr}${COLOR_RESET}${timePadding} |`);
    totalTime += time;
  }

  console.log(`+-${'-'.repeat(col1Width)}-+-${'-'.repeat(col2Width)}-+`);
  const totalTimeStr = totalTime.toFixed(2) + " ms";
  const totalPadding = ' '.repeat(Math.max(0, col2Width - totalTimeStr.length));
  console.log(`| ${COLOR_BOLD}${'TOTAL RUNTIME (simulator)'.padEnd(col1Width)}${COLOR_RESET} | ${COLOR_BOLD}${COLOR_SUCCESS}${totalTimeStr}${COLOR_RESET}${totalPadding} |`);
  console.log(`+-${'-'.repeat(col1Width)}-+-${'-'.repeat(col2Width)}-+`);
}

run().catch(err => {
  console.error(`\n${COLOR_ERROR}❌ Fatal error during test execution:${COLOR_RESET}`, err);
  process.exit(1);
});
