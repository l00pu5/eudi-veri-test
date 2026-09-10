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
 *   --mode=6 (deferred):  Deferred issuance simulation with async handshake 
 * 
 * Execution:
 *   node eudi-test-harness_demo.js --mode=4
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');

let API_BASE = 'http://localhost:3000';

// ANSI escape codes for colored terminal output
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
  throw new Error("Unsupported CBOR data type: " + typeof val);
}

// aux function for base64url encoding
function base64url(strOrBuffer) {
  const buffer = Buffer.isBuffer(strOrBuffer) ? strOrBuffer : Buffer.from(strOrBuffer);
  return buffer.toString('base64url');
}

// aux function for JWK thumbprint
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
 * Concat KDF in accordance with RFC 7518 for CEK derivation (AES-128-GCM)
 */
function deriveConcatKDF(sharedSecret, keyLenBytes, alg) {
  const roundOutputs = [];
  let counter = 1;
  const keyLenBits = keyLenBytes * 8;

  const algBuffer = Buffer.from(alg, 'ascii');
  const suppPubInfo = Buffer.alloc(4);
  suppPubInfo.writeUInt32BE(keyLenBits, 0);

  const fixedInfo = Buffer.concat([
    algBuffer,
    Buffer.alloc(4), // PartyUInfo length 0
    Buffer.alloc(4), // PartyVInfo length 0
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
    rTimes[label] = Number(end - start) / 1_000_000; // ms
    return res;
  }
}

// ensures that demo-keys.json exists to assure standalone capabilities
function ensureDemoKeysExist() {
  const scratchDir = '.';
  if (!fs.existsSync(scratchDir)) {
    fs.mkdirSync(scratchDir, { recursive: true });
  }
  const keysPath = `${scratchDir}/demo-keys.json`;
  if (!fs.existsSync(keysPath)) {
    console.log(`${COLOR_WARN}⚠️  No active demo-keys.json found. Generating temporary demo trust keys...${COLOR_RESET}`);
    const walletKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const walletPrivateKeyPem = walletKey.privateKey.export({ type: 'sec1', format: 'pem' });
    const walletPublicKeyPem = walletKey.publicKey.export({ type: 'spki', format: 'pem' });

    const demoKeys = {
      demoWalletKeys: {
        privateKey: walletPrivateKeyPem,
        publicKey: walletPublicKeyPem
      }
    };
    fs.writeFileSync(keysPath, JSON.stringify(demoKeys, null, 2));
    console.log(`  ✔ Temporary demo-keys.json generated successfully.`);
  }
}

// Deferred Credentials Issuance mock server instance
function startMockDeferredServer() {
  let pollCount = 0;
  const server = http.createServer((req, res) => {
    const url = req.url;
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'GET' && url === '/api/issuance/initiate') {
      res.writeHead(200);
      res.end(JSON.stringify({
        sessionId: 'deferred_mock_session_9988',
        wiaChallenge: 'deferred_mock_wia_challenge_7766'
      }));
    } else if (req.method === 'POST' && url === '/api/issuance/nonce') {
      res.writeHead(200);
      res.end(JSON.stringify({
        c_nonce: 'mock_deferred_c_nonce_123',
        dpop_nonce: 'mock_deferred_dpop_nonce_456'
      }));
    } else if (req.method === 'POST' && url === '/api/issuance/token') {
      res.writeHead(200);
      res.end(JSON.stringify({
        access_token: 'mock_deferred_access_token_xyz',
        token_type: 'DPoP',
        expires_in: 3600
      }));
    } else if (req.method === 'POST' && url === '/api/issuance/credential') {
      console.log(`   ${COLOR_WARN}[Mock Server] Credential endpoint ha been invoked. Simulating time-intensive background validation activites...${COLOR_RESET}`);
      console.log(`   ${COLOR_WARN}[Mock Server] Replying with HTTP 202 (Accepted) & transaction_id: tx_req_88192A${COLOR_RESET}`);
      res.writeHead(202);
      res.end(JSON.stringify({
        transaction_id: 'tx_req_88192A',
        interval: 2 // polling interval: 2s
      }));
    } else if (req.method === 'POST' && url === '/api/issuance/deferred') {
      pollCount++;
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        const parsed = JSON.parse(body || '{}');
        console.log(`   ${COLOR_CYAN}[Mock Server] Polling at /deferred endpoint (poll attempt #${pollCount}) for transaction_id: ${parsed.transaction_id}${COLOR_RESET}`);

        if (pollCount < 2) {
          console.log(`   ${COLOR_WARN}[Mock Server] Status still 'pending'... Sending HTTP 202 (Accepted) again.${COLOR_RESET}`);
          res.writeHead(202);
          res.end(JSON.stringify({
            transaction_id: 'tx_req_88192A',
            interval: 2
          }));
        } else {
          console.log(`   ${COLOR_SUCCESS}[Mock Server] Status 'complete'! Signing Erika Mustermann SD-JWT PID...${COLOR_RESET}`);

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

          const finalCredential = `${issuerJwt}~${DISCLOSURE_1}~${DISCLOSURE_2}~${DISCLOSURE_3}~${DISCLOSURE_4}~${DISCLOSURE_5}~`;

          res.writeHead(200);
          res.end(JSON.stringify({
            credentials: [{
              credential: finalCredential
            }]
          }));
        }
      });
    } else {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'Not Found' }));
    }
  });

  server.listen(3100);
  return server;
}

async function run() {
  const args = process.argv.slice(2);
  let modeArg = args.find(arg => arg.startsWith('--mode='));
  let mode = modeArg ? modeArg.split('=')[1] : '3'; // Default: Mode 3 (E2E)

  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`${COLOR_BOLD}${COLOR_INFO}📱 EUDI WALLET - TEST HARNESS & CLIENT${COLOR_RESET}`);
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`Selected mode: ${COLOR_BOLD}${COLOR_WARN}Modus ${mode}${COLOR_RESET}`);

  if (mode === '1') {
    console.log(`Descriptipn: Unencrypted direct_post presentation (mock claims)`);
    await runPresentation(false, null);
  } else if (mode === '2') {
    console.log(`Description: Encrypted direct_post.jwt presentation (JWE via ECDH-ES)`);
    await runPresentation(true, null);
  } else if (mode === '3') {
    console.log(`Description: Full E2E pipeline (issuance + JWE-encrypted presentation)`);
    const issuedCredential = await runIssuance('dc+sd-jwt', false);
    await runPresentation(true, issuedCredential);
  } else if (mode === '4') {
    console.log(`Description: mdoc (mDL) presentation with binary DeviceResponse CBOR simulation`);
    await runMdocPresentation(true); // mdoc mit JWE verschlüsselt senden
  } else if (mode === '5') {
    console.log(`Description: Full mDL E2E pipeline (mDL issuance + mdoc presentation)`);
    const issuedCredential = await runIssuance('mso_mdoc', false);
    await runMdocPresentation(true, issuedCredential);
  } else if (mode === '6') {
    console.log(`Description: polling scenario for deferred issuance (delayed credential issuance simulation)`);

    ensureDemoKeysExist();
    const mockServer = startMockDeferredServer();
    API_BASE = 'http://localhost:3100'; // redirect to internal credential issuer mock server (deferred issuance scenario)

    let issuedCredential;
    try {
      issuedCredential = await runIssuance('dc+sd-jwt', true); // executed deferred flow including continuous polling
    } finally {
      // destroy mock server instance & free port
      mockServer.close();
      console.log(`[Mock Server] Server instance terminated successfully.`);
    }

    // completing presentation scenario on the verifier instance (port 3000)
    API_BASE = 'http://localhost:3000'; // redirect to verifier instance
    try {
      console.log(`\\n${COLOR_INFO}Attemtping to present the deferred SD-JWT PID to the verifier...${COLOR_RESET}`);
      await runPresentation(true, issuedCredential);
    } catch (err) {
      console.log(`\\n${COLOR_WARN}⚠️  Note: optional presentation could not be completed; server not reachable on port 3000.${COLOR_RESET}`);
      console.log(`  (Launch 'node eudi-verifier-server_demo.js' in a dedicated terminal)${COLOR_RESET}`);
    }
  } else {
    console.error(`${COLOR_ERROR}❌ Invalid mode: ${mode}. Supported modes: 1-6${COLOR_RESET}`);
    process.exit(1);
  }

  printStatsTable();
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * STEP A: ISSUANCE PROCESS (OpenID4VCI)
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function runIssuance(format = 'dc+sd-jwt', isDeferredScenario = false) {
  console.log(`\\n${COLOR_INFO}--- PHASE 1: DYNAMIC PID ISSUANCE (OpenID4VCI) ---${COLOR_RESET}`);
  console.log(`  Format: ${COLOR_BOLD}${format}${COLOR_RESET}`);

  ensureDemoKeysExist();
  const keysPath = './demo-keys.json';

  console.log(`[VCI 1] Loading PKI keys of wallet provider...`);
  const demoKeys = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  console.log(`  ✔ Keys loaded successfully.`);

  console.log(`[VCI 2] Generating ephemeral wallet and device binding keys (P-256)...`);
  const walletKeyPair = trackTime('Key generation: wallet (P-256)', () =>
    crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  );
  const deviceKeyPair = trackTime('Key generation: device binding (P-256)', () =>
    crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  );
  const walletPubKeyJwk = walletKeyPair.publicKey.export({ format: 'jwk' });
  const devicePubKeyJwk = deviceKeyPair.publicKey.export({ format: 'jwk' });

  console.log(`[VCI 3] Initiating issuance session...`);
  const initResponse = await trackTime('HTTP: Initiating VCI Session',
    fetch(`${API_BASE}/api/issuance/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format: format })
    }).then(res => res.json())
  );
  const { sessionId, wiaChallenge } = initResponse;
  console.log(`  ✔ Session initiated. ID: ${sessionId}`);

  console.log(`[VCI 4] Fetching one-time nonce from nonce endpoint...`);
  const nonceResponse = await trackTime('HTTP: Fetching VCI Nonce',
    fetch(`${API_BASE}/api/issuance/nonce`, { method: 'POST' }).then(res => res.json())
  );

  console.log(`[VCI 5] Preparing WIA & WIA PoP...`);
  const wiaToken = trackTime('Krypto: Signiere WIA JWT', () => {
    const header = { alg: 'ES256', typ: 'oauth-client-attestation+jwt' };
    const payload = {
      iss: 'https://wallet-provider.de',
      sub: 'https://wallet.example.com/instances/12345',
      cnf: { jwk: walletPubKeyJwk }
    };
    return signJws(header, payload, demoKeys.demoWalletKeys.privateKey);
  });

  const wiaPop = trackTime('Crypto: Signing WIA-PoP JWT', () => {
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

  console.log(`[VCI 8] Generating Device-Binding Proof...`);
  const credNonces = await trackTime('HTTP: Fetching VCI Credential Nonce',
    fetch(`${API_BASE}/api/issuance/nonce`, { method: 'POST' }).then(res => res.json())
  );

  const credDpopProof = trackTime('Crypto: Signing Credential DPoP Proof', () => {
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletPubKeyJwk };
    const payload = {
      htm: 'POST',
      htu: `${API_BASE}/api/issuance/credential`,
      nonce: credNonces.dpop_nonce
    };
    return signJws(header, payload, walletKeyPair.privateKey);
  });

  const popProofJwt = trackTime('Crypto: Signing Device Binding PoP (c_nonce)', () => {
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

  const credResponseRaw = await trackTime('HTTP: Sending Credential Request (/credential)',
    fetch(`${API_BASE}/api/issuance/credential`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `DPoP ${tokenResponse.access_token}`,
        'DPoP': credDpopProof
      },
      body: JSON.stringify(credRequestPayload)
    })
  );

  let issuedCredential;

  // Deferred Issuance Scenario (=> HTTP 202)
  if (credResponseRaw.status === 202) {
    const deferredInit = await credResponseRaw.json();
    const transactionId = deferredInit.transaction_id;
    let interval = deferredInit.interval || 2;

    console.log(`\\n${COLOR_WARN}⏳ [DEFERRED] HTTP 202 (Accepted). Issuance is delayed!${COLOR_RESET}`);
    console.log(`  ➡ transaction_id: ${COLOR_BOLD}${transactionId}${COLOR_RESET}`);
    console.log(`  ➡ polling interval: ${interval} seconds`);

    let polling = true;
    let pollCount = 0;

    while (polling) {
      console.log(`\\n[VCI 9.1] Waiting ${interval}s before next poll...`);
      await new Promise(resolve => setTimeout(resolve, interval * 1000));
      pollCount++;

      console.log(`[VCI 9.2] Sending polling request #${pollCount} to deferred endpoint (/api/issuance/deferred)...`);

      // preparing DPoP proof for deferrend endpoint
      const deferredDpopProof = trackTime(`Crypto: Signing Deferred DPoP Proof #${pollCount}`, () => {
        const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletPubKeyJwk };
        const payload = {
          htm: 'POST',
          htu: `${API_BASE}/api/issuance/deferred`,
          nonce: credNonces.dpop_nonce
        };
        return signJws(header, payload, walletKeyPair.privateKey);
      });

      const pollResponseRaw = await trackTime(`HTTP: Deferred Poll #${pollCount}`,
        fetch(`${API_BASE}/api/issuance/deferred`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `DPoP ${tokenResponse.access_token}`,
            'DPoP': deferredDpopProof
          },
          body: JSON.stringify({ transaction_id: transactionId })
        })
      );

      if (pollResponseRaw.status === 202) {
        const pollData = await pollResponseRaw.json();
        console.log(`   ${COLOR_WARN}⏳ [DEFERRED] Status remains 'pending'... (waiting for release)${COLOR_RESET}`);
        interval = pollData.interval || 2;
      } else if (pollResponseRaw.status === 200) {
        const pollData = await pollResponseRaw.json();
        issuedCredential = pollData.credentials[0].credential;
        console.log(`   ${COLOR_SUCCESS}✔ [DEFERRED] Credential released successfully!${COLOR_RESET}`);
        polling = false;
      } else {
        const errText = await pollResponseRaw.text();
        throw new Error(`Error while polling: HTTP ${pollResponseRaw.status} - ${errText}`);
      }
    }
  } else {
    const credResponse = await credResponseRaw.json();
    issuedCredential = credResponse.credentials[0].credential;
  }

  console.log(`${COLOR_SUCCESS}✅ Credential issued successfully! (length: ${issuedCredential.length} chars)${COLOR_RESET}`);

  return {
    credential: issuedCredential,
    devicePrivateKey: deviceKeyPair.privateKey,
    devicePubKeyJwk: devicePubKeyJwk
  };
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * STEP B: PRESENTATION PROCESS (OpenID4VP)
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function runPresentation(useEncryption, issuedData) {
  console.log(`\\n${COLOR_INFO}--- PHASE 2: PID PRESENTATION (OpenID4VP) ---${COLOR_RESET}`);

  console.log(`[VP 1] Initiating presentation session at the verifier...`);
  const initResponse = await trackTime('HTTP: Initiating VP Session',
    fetch(`${API_BASE}/api/presentation/initiate`).then(res => res.json())
  );
  const { sessionId, qrCodeUrl } = initResponse;
  console.log(`  ✔ Session initiated successfully. ID: ${sessionId}`);

  console.log(`[VP 2] Retrieving JAR via request_uri...`);
  const requestUri = new URL(qrCodeUrl).searchParams.get('request_uri');
  const signedJar = await trackTime('HTTP: Hole JAR Request',
    fetch(requestUri).then(res => res.text())
  );

  const jarPayloadB64 = signedJar.split('.')[1];
  const jarPayload = JSON.parse(Buffer.from(jarPayloadB64, 'base64url').toString('utf8'));
  const nonce = jarPayload.nonce;
  const rpKeyJwk = jarPayload.client_metadata?.jwks?.keys[0];

  console.log(`  ✔ JAR retrieved successfully.`);
  console.log(`  ✔ Presentation nonce: ${nonce}`);

  console.log(`[VP 3] Preparing presentation payload (SD-JWT VC + Key Binding)...`);
  let finalSdJwt;
  let presentationDevicePrivateKey;

  if (issuedData) {
    console.log(`  👉 Using dynamically generated PID.`);
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

    const kbJwt = trackTime('Crypto: Signing Key-Binding (KB-JWT)', () =>
      signJws(kbHeader, kbPayload, presentationDevicePrivateKey)
    );

    finalSdJwt = `${issuerJwt}~${disclosures.join('~')}~${kbJwt}`;
  } else {
    console.log(`  👉 Using static mock PID (Erika Mustermann).`);
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
    console.log(`[VP 4] Encrypted presentation via JWE (ECDH-ES + AES-128-GCM)...`);

    const walletEncKeyPair = trackTime('Key generation: ephemeral VP key (P-256)', () =>
      crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    );
    const walletEncPubKeyJwk = walletEncKeyPair.publicKey.export({ format: 'jwk' });

    const rpPublicKey = crypto.createPublicKey({ key: rpKeyJwk, format: 'jwk' });
    const sharedSecret = trackTime('Crypto: ECDH Key Agreement', () =>
      crypto.diffieHellman({
        privateKey: walletEncKeyPair.privateKey,
        publicKey: rpPublicKey
      })
    );

    const cek = trackTime('Crypto: Concat KDF Key Derivation', () =>
      deriveConcatKDF(sharedSecret, 16, 'A128GCM')
    );

    const jweString = trackTime('Crypto: AES-128-GCM JWE Encryption', () => {
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

    console.log(`  ✔ JWE encryption completed. JWE (shortened): ${jweString.substring(0, 50)}...`);
    postBodyString = `response=${encodeURIComponent(jweString)}&state=${encodeURIComponent(sessionId)}`;
  } else {
    console.log(`[VP 4] Sending unenecrypted payload (direct_post fallback)...`);
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
  console.log(`  ✔ Server responds with redirect URI: ${callbackResponse.redirect_uri}`);

  console.log(`[VP 6] Querying final verification status from server...`);
  const statusResponse = await trackTime('HTTP: Polling Onboarding Status',
    fetch(`${API_BASE}/api/presentation/status?sid=${sessionId}`).then(res => res.json())
  );

  console.log(`\\n${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`${COLOR_BOLD}${COLOR_SUCCESS}🎯 STATUS OF PRESENTATION VERIFICATION: ${statusResponse.status}${COLOR_RESET}`);
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`Transport encryption (JWE): ${COLOR_BOLD}${statusResponse.isEncrypted ? 'YES 🔒 (direct_post.jwt)' : 'NO ⚠️ (direct_post)'}${COLOR_RESET}`);
  console.log(`Übertragene Claims:`);
  console.log(JSON.stringify(statusResponse.claims, null, 2));
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}\\n`);
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * SCHRITT C: MDOC PRESENTATION PROCESS (MODE 4 / MODE 5)
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function runMdocPresentation(useEncryption, issuedData) {
  console.log(`\\n${COLOR_INFO}--- PID PRESENTATION IN ISO MDOC FORMAT (mDL) ---${COLOR_RESET}`);

  console.log(`[mdoc 1] Initiating presentation session at the verifier...`);
  const initResponse = await trackTime('HTTP: Initiating mdoc Session',
    fetch(`${API_BASE}/api/presentation/initiate`).then(res => res.json())
  );
  const { sessionId, qrCodeUrl } = initResponse;
  console.log(`  ✔ Session initiated successfully. ID: ${sessionId}`);

  console.log(`[mdoc 2] Fetching JAR via request_uri...`);
  const requestUri = new URL(qrCodeUrl).searchParams.get('request_uri');
  const signedJar = await trackTime('HTTP: Fetching JAR Request',
    fetch(requestUri).then(res => res.text())
  );

  const jarPayloadB64 = signedJar.split('.')[1];
  const jarPayload = JSON.parse(Buffer.from(jarPayloadB64, 'base64url').toString('utf8'));
  const nonce = jarPayload.nonce;
  const rpKeyJwk = jarPayload.client_metadata?.jwks?.keys[0];

  console.log(`  ✔ Extracted presentation nonce: ${nonce}`);

  console.log(`[mdoc 3] Generating SessionTranscript (ISO 18013-5)...`);

  const rpClientId = "x509_san_dns:client.example.org";
  const responseUri = `${API_BASE}/api/presentation/callback`;

  let jwkThumbprint = null;
  if (useEncryption && rpKeyJwk) {
    jwkThumbprint = trackTime('Crypto: Calculating JWK Thumbprint (RFC 7638)', () => getJwkThumbprint(rpKeyJwk));
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

  const sessionTranscriptCbor = trackTime('CBOR: Encoding SessionTranscript', () => encodeCBOR(sessionTranscript));
  console.log(`  ✔ SessionTranscript CBOR generated (${sessionTranscriptCbor.length} bytes).`);

  console.log(`[mdoc 4] Generating mdoc document and signing device binding...`);

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

    const jweString = trackTime('Crypto: AES-128-GCM JWE Encryption', () => {
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
  const callbackResponse = await trackTime('HTTP: direct_post callback transmission',
    fetch(`${API_BASE}/api/presentation/callback`, {
      method: 'POST',
      headers: { 'Content-Type': postContentType },
      body: postBodyString
    }).then(res => res.json())
  );
  console.log(`  ✔ Server respons with redirect URI: ${callbackResponse.redirect_uri}`);

  console.log(`[mdoc 7] Querying final verification status from server...`);
  const statusResponse = await trackTime('HTTP: Polling Onboarding Status',
    fetch(`${API_BASE}/api/presentation/status?sid=${sessionId}`).then(res => res.json())
  );

  console.log(`\\n${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`${COLOR_BOLD}${COLOR_SUCCESS}🎯 STATUS OF PRESENTATION VERIFICATION: ${statusResponse.status}${COLOR_RESET}`);
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`Presentation format:             ${COLOR_BOLD}ISO mdoc (mDL)${COLOR_RESET}`);
  console.log(`Transport encryption (JWE):  ${COLOR_BOLD}${statusResponse.isEncrypted ? 'YES 🔒 (direct_post.jwt)' : 'NO ⚠️ (Klartext direct_post)'}${COLOR_RESET}`);
  console.log(`Transmitted mDL claims:`);
  console.log(JSON.stringify(statusResponse.claims, null, 2));
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}\\n`);
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * PRINT STATS TABLE
 * ─────────────────────────────────────────────────────────────────────────────
 */
function printStatsTable() {
  console.log(`${COLOR_BOLD}${COLOR_CYAN}📊 CONSOLIDATED RUNTIME STATS OF THE TRANSACTION${COLOR_RESET}`);

  const col1Width = 55;
  const col2Width = 14;

  console.log(`+-${'-'.repeat(col1Width)}-+-${'-'.repeat(col2Width)}-+`);
  console.log(`| ${COLOR_BOLD}${'Action / cryptographic step'.padEnd(col1Width)}${COLOR_RESET} | ${COLOR_BOLD}${'Runtime'.padEnd(col2Width)}${COLOR_RESET} |`);
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
  console.log(`| ${COLOR_BOLD}${'TOTAL RUNTIME (Simulator)'.padEnd(col1Width)}${COLOR_RESET} | ${COLOR_BOLD}${COLOR_SUCCESS}${totalTimeStr}${COLOR_RESET}${totalPadding} |`);
  console.log(`+-${'-'.repeat(col1Width)}-+-${'-'.repeat(col2Width)}-+`);
}

run().catch(err => {
  console.error(`\\n${COLOR_ERROR}❌ Fatal error during test execution:${COLOR_RESET}`, err);
  process.exit(1);
});
