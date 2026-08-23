/**
 * EUDI Wallet - JWE Encryption Test Client (Simulator)
 * 
 * This script simulates JWE encryption / direct_post.jwt
 * 
 * It will simulate a full onboarding flow against the Express backend server:
 * 
 * 1. GET /api/presentation/initiate    - Fetch QR code and session ID
 * 2. GET /api/presentation/request-jwt - Fetch signed JAR with RP encryption key
 * 3. Cryptographic ECDH key exchange & AES-GCM encryption (JWE) of the Erika Mustermann PID
 * 4. POST /api/presentation/callback   - Send encrxypted JWE to direct_post endpoint
 * 5. GET /api/presentation/status      - Check if the server has successfully decrypted the JWE
 */

const crypto = require('crypto');
const http = require('http');

const SERVER_URL = 'http://localhost:3000';

// aux function for executing HTTP requests as Promise
function makeRequest(url, method = 'GET', headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const options = {
      hostname: u.hostname,
      port: u.port || 80,
      path: u.pathname + u.search,
      method: method,
      headers: headers
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on('error', (e) => reject(e));
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

/**
 * Concat KDF (RFC 7518 section 4.6.2) for CEK derivation
 */
function deriveConcatKDF(sharedSecret, keyLenBytes, alg) {
  const roundOutputs = [];
  let counter = 1;
  const keyLenBits = keyLenBytes * 8;

  const algBuffer = Buffer.from(alg, 'ascii');
  const suppPubInfo = Buffer.alloc(4);
  suppPubInfo.writeUInt32BE(keyLenBits, 0);

  // fixedInfo: AlgorithmID || PartyUInfo (empty) || PartyVInfo (empty) || SuppPubInfo
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

// Haupt-Testablauf
async function runJweTest() {
  console.log('================================================================');
  console.log('🚀 STARTING EUDI WALLET JWE (direct_post.jwt) SIMULATOR');
  console.log('================================================================\n');

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 1: SESSION INITIATION
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[Step 1] Initiating onboarding session at the verifier...');
  let initRes;
  try {
    initRes = await makeRequest(`${SERVER_URL}/api/presentation/initiate`);
  } catch (e) {
    console.error('❌ Error while connecting to the server. Ensure that the server is running on port 3000');
    process.exit(1);
  }

  const initData = JSON.parse(initRes.body);
  const sessionId = initData.sessionId;
  const qrCodeUrl = initData.qrCodeUrl;
  console.log(`   ✔ Session created. ID: ${sessionId}`);
  console.log(`   ✔ QR code content (openid4vp://): ${qrCodeUrl}\n`);

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 2: REQUEST OBJECT (JAR) PROVISION
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[Step 2] Simulating wallet: fetching request object (JAR) via request_uri...');
  const requestUri = new URL(qrCodeUrl).searchParams.get('request_uri');
  console.log(`   -> Fetching JAR from: ${requestUri}`);

  const jarRes = await makeRequest(requestUri);
  const jarToken = jarRes.body;

  // deconding payload decodieren (2nd JWT segment)
  const jarPayloadB64 = jarToken.split('.')[1];
  const jarPayload = JSON.parse(Buffer.from(jarPayloadB64, 'base64url').toString('utf8'));
  const nonce = jarPayload.nonce;
  const rpKeyJwk = jarPayload.client_metadata.jwks.keys[0];

  console.log(`   ✔ JAR retrievd successfully.`);
  console.log(`   ✔ Extracted transaction nonce: ${nonce}`);
  console.log(`   ✔ Received RP encryption key (JWK kid): ${rpKeyJwk.kid}\n`);

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 3: GENERATED ENCRYPTED JWE PAYLOAD (Erika Mustermann mockup)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[Step 3] Preparing Erika Mustermann direct_post.jwt payload...');

  // 1. Generating unencrypted presentation data (SD-JWT VC + KB-JWT)
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

  const fullSdJwt = `${issuerJwt}~${DISCLOSURE_1}~${DISCLOSURE_2}~${DISCLOSURE_3}~${DISCLOSURE_4}~${DISCLOSURE_5}~${kbJwt}`;

  // to-be-encrypted payload
  const cleartextPayload = {
    vp_token: {
      my_identity_credential: [fullSdJwt]
    },
    wia_token: `eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.${Buffer.from(JSON.stringify({
      iss: "https://wallet-provider-backend.eudi-wallet.de",
      sub: "https://wallet.example.com/instances/12345",
      wallet_name: "EUDI National Reference Wallet",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    })).toString('base64url')}.simulated_wallet_manufacturer_signature`
  };

  console.log('   -> Generating ephemeral wallet key pair for ECDH key exchange...');
  // 2. wallet is generating own P-256 key pair
  const walletKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const walletEphemeralPubKeyJwk = walletKeyPair.publicKey.export({ format: 'jwk' });

  // 3. importing public key of RP
  const rpPublicKey = crypto.createPublicKey({
    key: rpKeyJwk,
    format: 'jwk'
  });

  // 4. calculating shared secret (ECDH shared secret)
  const sharedSecret = crypto.diffieHellman({
    privateKey: walletKeyPair.privateKey,
    publicKey: rpPublicKey
  });

  // 5. deriving symmetric CEK (Content Encryption Key) via concat KDF (AES-128-GCM -> 16 Bytes)
  const cek = deriveConcatKDF(sharedSecret, 16, 'A128GCM');

  // 6. executing symmetric encryption (AES-128-GCM)
  const jweHeader = {
    alg: 'ECDH-ES',
    enc: 'A128GCM',
    epk: walletEphemeralPubKeyJwk
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

  // 7. composing JWE compact string (5 segments: Header..IV.Ciphertext.Tag)
  const jweString = `${headerB64}..${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${tag.toString('base64url')}`;

  console.log('   ✔ JWE end-to-end encryption completed!');
  console.log(`   ✔ Encrypted JWE token (shortened): ${jweString.substring(0, 80)}...\n`);

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 4: DIRECT_POST.JWT CALLBACK TRANSMISSION
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[Step 4] Transmitting encrypted JWE via direct_post.jwt callback to server...');

  // direct_post.jwt hands over JWE in field 'response'
  const postData = `response=${encodeURIComponent(jweString)}&state=${encodeURIComponent(sessionId)}`;

  const callbackRes = await makeRequest(
    `${SERVER_URL}/api/presentation/callback`,
    'POST',
    {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(postData)
    },
    postData
  );

  const callbackData = JSON.parse(callbackRes.body);
  console.log(`   ✔ Callbacl reply received (HTTP ${callbackRes.statusCode})`);
  console.log(`   ✔ Received redirect URI: ${callbackData.redirect_uri}\n`);

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 5: STATUS POLLING (CHECK VERIFICATION STATUS)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[Step 5] Querying verification and encryption status from server...');
  const statusRes = await makeRequest(`${SERVER_URL}/api/presentation/status?sid=${sessionId}`);
  const statusData = JSON.parse(statusRes.body);

  console.log('================================================================');
  console.log('🎯 RESULT OF PRESENTATION VERIFICATION IN SANDBOX');
  console.log('================================================================');
  console.log(JSON.stringify(statusData, null, 2));
  console.log('================================================================');

  if (statusData.status === 'SUCCESS' && statusData.isEncrypted === true) {
    console.log('🎉 SUCCESS: server was able to decrypt JWE token correctly!');
    console.log('🔒 Mock identity has been verified in an encrypted state.');
  } else {
    console.error('❌ ERROR: onboarding state is not succesful or not encrypted.');
  }
}

// Test ausführen
runJweTest().catch(err => {
  console.error('Critical error:', err);
});
