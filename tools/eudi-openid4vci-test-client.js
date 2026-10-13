/**
 * EUDI Wallet - OpenID4VCI (Verifiable Credential Issuance) Test Client
 * 
 * This module simulates the behavior of a wallet app when requesting + device binding
 * a PID from the credential endpoint of the PID provider (PIDP).
 * 
 * It executes an OpenID4VCI interface flow:
 * 1. Abruf der dynamischen Server-Schlüssel (simulierter Trust-Store)
 * 2. Session initialization (retrieving the WIA challenge)
 * 3. Nonce handshake (retrieving the one-time nonce)
 * 4. Signing the WIA & WIA Proof-of-Possession (WIA-PoP)
 * 5. Signing the DPoP proof (sender constrainting)
 * 6. Token exchange (/token): fetching the DPoP-bound access token
 * 7. Generating a local user PID key pairs (device binding)
 * 8. Signing the key PoP (Proof of Possession) via c_nonce
 * 9. Retrieving the PID (/credential): fetching and decoding the signed SD-JWT VC
 * 
 * The Express backend needs to be running to facilitate the simulation:
 *   node eudi-verifier-server.js
 */

const crypto = require('crypto');
const fs = require('fs');

const API_BASE = 'http://localhost:3000';

// aux function for base64url encoding
function base64url(strOrBuffer) {
  const buffer = Buffer.isBuffer(strOrBuffer) ? strOrBuffer : Buffer.from(strOrBuffer);
  return buffer.toString('base64url');
}

// aux function for signing the JWS token (native ES256)
function signJws(header, payload, privateKeyPem) {
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const dataToSign = `${headerB64}.${payloadB64}`;

  const signer = crypto.createSign('SHA256');
  signer.update(dataToSign);
  const signature = signer.sign(privateKeyPem, 'base64url');

  return `${dataToSign}.${signature}`;
}

async function runVciTest() {
  console.log('================================================================');
  console.log('🚀 STARTING EUDI WALLET OpenID4VCI PID ISSUANCE SIMULATOR');
  console.log('================================================================\n');

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 1: CHECK SERVER AND LOAD DEMO KEYS (TRUST STORE)
  // ─────────────────────────────────────────────────────────────────────────
  const keysPath = './demo-keys.json';
  if (!fs.existsSync(keysPath)) {
    console.error('❌ Error: no active demo keys were found!');
    console.error('Please start the Express server:');
    console.error('  node eudi-verifier-server.js');
    process.exit(1);
  }

  console.log('[Step 1] Loading PKI key from wallet provider...');
  const demoKeys = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  console.log('   ✔ Wallet provider keys loaded successfully.');
  console.log('   ✔ Generating own ephemeral wallet and device keys (P-256)...');

  // Generating wallet-spezific keys (for DPoP & WIA-PoP)
  const walletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const walletPublicKeyJwk = walletKeys.publicKey.export({ format: 'jwk' });

  // Generating device-related proof key pair (fo device binding of the PID)
  const deviceKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const devicePublicKeyJwk = deviceKeys.publicKey.export({ format: 'jwk' });

  // ─────────────────────────────────────────────────────────────────────────
  // SCHRITT 2: SESSION INITIATION AT THE ISSUER
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Step 2] Initiating issuance session at the issuer...');
  const initResponse = await fetch(`${API_BASE}/api/issuance/initiate`).then(res => res.json());
  if (!initResponse.success) {
    throw new Error('Session initiation failed: ' + JSON.stringify(initResponse));
  }
  const { sessionId, wiaChallenge } = initResponse;
  console.log(`   ✔ Session created. ID (wia_challenge_sid): ${sessionId}`);
  console.log(`   ✔ Receved WIA challenge: ${wiaChallenge}`);

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 3: EINMAL-NONCES VOM NONCE-ENDPOINT ABRUFEN
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Step 3] Fetching nonces from nonce endpoint...');
  const nonceResponse = await fetch(`${API_BASE}/api/issuance/nonce`, { method: 'POST' }).then(res => res.json());
  console.log('   ✔ Nonces retrieved:', JSON.stringify(nonceResponse, null, 2));

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 4: GENERATE WIA & WIA-POP TOKENS
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Step 4] Preparing WIA...');

  // WIA (signed by wallet backend; simulated via demoWalletKeys)
  const wiaHeader = { alg: 'ES256', typ: 'oauth-client-attestation+jwt' };
  const wiaPayload = {
    iss: 'https://wallet-provider.de',
    sub: 'https://wallet.de/instances/456',
    cnf: { jwk: walletPublicKeyJwk } // binding of the wallet to our wallet public key
  };
  const wiaToken = signJws(wiaHeader, wiaPayload, demoKeys.demoWalletKeys.privateKey);
  console.log('   ✔ Wallet Instance Attestation (WIA) has been generated.');

  // WIA-PoP (signed by local device by using the challenge)
  const popHeader = { alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' };
  const popPayload = {
    iss: 'https://wallet-provider.de',
    aud: `${API_BASE}/api/issuance`,
    challenge: wiaChallenge
  };
  const wiaPop = signJws(popHeader, popPayload, walletKeys.privateKey);
  console.log('   ✔ WIA Proof of Possession (PoP) has been generated.');

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 5: GENERATE DPOP FOR TOKEN RETRIEVAL
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Step 5] Generating DPoP proof for token interface (sender constrainting)...');
  const tokenDpopHeader = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletPublicKeyJwk };
  const tokenDpopPayload = {
    htm: 'POST',
    htu: `${API_BASE}/api/issuance/token`,
    nonce: nonceResponse.dpop_nonce // binding to DPoP nonce for replay prevention
  };
  const tokenDpopProof = signJws(tokenDpopHeader, tokenDpopPayload, walletKeys.privateKey);

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 6: TOKEN EXCHANGE (/token)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Step 6] Sending token request to token endpoint...');
  const tokenRequestBody = {
    code: 'dummy_auth_code_123',
    code_verifier: 'dummy_code_verifier_123',
    client_assertion: wiaToken,
    client_assertion_pop: wiaPop,
    wia_challenge_sid: sessionId
  };

  const tokenResponse = await fetch(`${API_BASE}/api/issuance/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'DPoP': tokenDpopProof
    },
    body: JSON.stringify(tokenRequestBody)
  }).then(async res => {
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Token endpoint error (${res.status}): ${errText}`);
    }
    return res.json();
  });

  console.log('   ✔ Token exxchanged successfully ! Received access data:');
  console.log(`     - Access token (shortened): Bearer ${tokenResponse.access_token.substring(0, 25)}...`);
  console.log(`     - Token type: ${tokenResponse.token_type}`);
  console.log(`     - New c_nonce for credential endpoint: ${tokenResponse.c_nonce}`);

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 7: CREATE DPOP & KEY POSSESSION PROOF (PoP) FOR PID RETRIEVAL
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Schritt 7] Preparing DPoP proof for credential endpoint...');

  // retrieving new nonces
  const credNonces = await fetch(`${API_BASE}/api/issuance/nonce`, { method: 'POST' }).then(res => res.json());

  // DPoP Proof for credential endpoint (wallet key bound to access token)
  const credDpopHeader = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletPublicKeyJwk };
  const credDpopPayload = {
    htm: 'POST',
    htu: `${API_BASE}/api/issuance/credential`,
    nonce: credNonces.dpop_nonce // fresh DPoP Nonce
  };
  const credDpopProof = signJws(credDpopHeader, credDpopPayload, walletKeys.privateKey);

  // PoP of PID (signed with new deviceKeys)
  const popProofHeader = { alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: devicePublicKeyJwk };
  const popProofPayload = {
    aud: `${API_BASE}/api/issuance`,
    nonce: credNonces.c_nonce // bindung to c_nonce for replay prevention
  };
  const popProofJwt = signJws(popProofHeader, popProofPayload, deviceKeys.privateKey);
  console.log('   ✔ Device Binding PoP-JWT has been generated.');

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 8: REQUEST PID (/credential)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Step 8] Requesting signed PID from credential endpoint...');
  const credRequestPayload = {
    credential_configuration_id: 'PID_SD_JWT_VC',
    proofs: {
      jwt: popProofJwt
    }
  };

  const credResponse = await fetch(`${API_BASE}/api/issuance/credential`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `DPoP ${tokenResponse.access_token}`,
      'DPoP': credDpopProof
    },
    body: JSON.stringify(credRequestPayload)
  }).then(async res => {
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Credential endpoint error (${res.status}): ${errText}`);
    }
    return res.json();
  });

  const issuedCredential = credResponse.credentials[0].credential;

  console.log('\n================================================================');
  console.log('🎉 SUCCESS: PID HAS BEEN ISSUED SUCCESSFULLY!');
  console.log('================================================================');
  console.log('\n--- RAW PID (SD-JWT VC) ---');
  console.log(issuedCredential);

  // decoding and vidualizing of main JWT and disclosed credentials
  const jwtPart = issuedCredential.split('~')[0];
  const decodedPayload = JSON.parse(Buffer.from(jwtPart.split('.')[1], 'base64url').toString('utf8'));

  console.log('\n--- UNPACKED MAIN JWT (signed by issuer) ---');
  console.log(JSON.stringify(decodedPayload, null, 2));

  console.log('\n--- SELECTIVELY DISCLOSED CLAIMS ---');
  const disclosures = issuedCredential.split('~').slice(1, -1);
  disclosures.forEach(disc => {
    const decodedDisc = JSON.parse(Buffer.from(disc, 'base64url').toString('utf8'));
    console.log(`   👉 ${decodedDisc[1]}: ${JSON.stringify(decodedDisc[2])} (Salt: ${decodedDisc[0]})`);
  });
  console.log('================================================================');
}

runVciTest().catch(err => {
  console.error('\n❌ Error in OpenID4VCI flow:', err.message);
});
