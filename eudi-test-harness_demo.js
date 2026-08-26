/**
 * EUDI Wallet - Unified Javascript Test Harness & E2E Integration Simulator (v7)
 * 
 * Dieses Skript ersetzt die alten plattformabhängigen Bash-Skripte vollständig durch
 * einen plattformunabhängigen, mathematisch korrekten Node.js-Simulator.
 * 
 * Es verwendet das native Node.js 'crypto'- und das globale 'fetch'-Modul (Node 18+).
 * 
 * Unterstützte Modi (auswählbar über Startargument --mode):
 *   --mode=1 (simple):    Unverschlüsselte direct_post-Präsentation (Erika Mustermann SD-JWT VC Mock).
 *   --mode=2 (encrypted): Verschlüsselte direct_post.jwt-Präsentation via JWE (ECDH-ES + AES-128-GCM).
 *   --mode=3 (e2e):       Vollständige eIDAS-Pipeline: Erst dynamische Ausstellung (OpenID4VCI)
 *                         gefolgt von verschlüsselter Präsentation (OpenID4VP) des frisch ausgestellten SD-JWT Ausweises!
 *   --mode=4 (mdoc):      CBOR- und mdoc-basierte mobile Führerschein-Präsentation (mDL) mit mathematisch korrektem
 *                         SessionTranscript und binärer DeviceResponse-CBOR-Simulation.
 * 
 * Ausführung:
 *   node eudi-test-harness-v3.js --mode=4
 */

const crypto = require('crypto');
const fs = require('fs');

const API_BASE = 'http://localhost:3000';

// ANSI-Escape-Codes für farbige Konsolenausgabe
const COLOR_RESET = '\x1b[0m';
const COLOR_INFO = '\x1b[34m';
const COLOR_SUCCESS = '\x1b[32m';
const COLOR_WARN = '\x1b[33m';
const COLOR_ERROR = '\x1b[31m';
const COLOR_CYAN = '\x1b[36m';
const COLOR_BOLD = '\x1b[1m';

// ─────────────────────────────────────────────────────────────────────────────
// ABHÄNGIGKEITSFREIER LIGHTWEIGHT CBOR-CODEC (GEMÄß RFC 8949)
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
      throw new Error("Gleitkommazahlen werden in dieser Krypto-Ebene nicht unterstützt.");
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
  throw new Error("Nicht unterstützter CBOR-Datentyp: " + typeof val);
}

// Hilfsfunktion für Base64url-Kodierung
function base64url(strOrBuffer) {
  const buffer = Buffer.isBuffer(strOrBuffer) ? strOrBuffer : Buffer.from(strOrBuffer);
  return buffer.toString('base64url');
}

// Hilfsfunktion für JWK Thumbprint (RFC 7638)
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

// Hilfsfunktion zum Signieren eines JWS-Tokens (Natives ES256)
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
 * Concat KDF gemäß RFC 7518 Sektion 4.6.2 zur CEK-Ableitung (AES-128-GCM)
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

// Zeitmessungs-Datenstruktur
const rTimes = {};
function trackTime(label, fnOrPromise) {
  const start = process.hrtime.bigint();
  if (fnOrPromise instanceof Promise) {
    return fnOrPromise.then(res => {
      const end = process.hrtime.bigint();
      rTimes[label] = Number(end - start) / 1_000_000; // in Millisekunden
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
  let mode = modeArg ? modeArg.split('=')[1] : '3'; // Default: Modus 3 (E2E)

  let sidArg = args.find(arg => arg.startsWith('--sid='));
  let externalSid = sidArg ? sidArg.split('=')[1] : null;

  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`${COLOR_BOLD}${COLOR_INFO}📱 EUDI WALLET - UNIFIED CRYPTO-TEST HARNESS & CLIENT (JS)${COLOR_RESET}`);
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`Gewählter Simulationsmodus: ${COLOR_BOLD}${COLOR_WARN}Modus ${mode}${COLOR_RESET}`);
  if (externalSid) {
    console.log(`Browser-Sitzungs-ID gekoppelt: ${COLOR_BOLD}${COLOR_SUCCESS}${externalSid}${COLOR_RESET}`);
  }

  if (mode === '1') {
    console.log(`Beschreibung: Unverschlüsselte direct_post-Präsentation (Mock-Claims).`);
    await runPresentation(false, null, externalSid);
  } else if (mode === '2') {
    console.log(`Beschreibung: Verschlüsselte direct_post.jwt-Präsentation (JWE via ECDH-ES).`);
    await runPresentation(true, null, externalSid);
  } else if (mode === '3') {
    console.log(`Beschreibung: Vollständige E2E-Pipeline (Ausstellung + JWE-verschlüsselte Präsentation).`);
    const issuedCredential = await runIssuance('dc+sd-jwt', externalSid);
    if (externalSid && externalSid.startsWith('session_iss_')) {
      console.log(`🎉 Erfolgreich! Ausweis wurde via OpenID4VCI an Browser-Sitzung ausgestellt.`);
    } else {
      await runPresentation(true, issuedCredential, externalSid);
    }
  } else if (mode === '4') {
    console.log(`Beschreibung: mdoc-Präsentationsmodus (mDL) mit binärer DeviceResponse-CBOR-Simulation.`);
    await runMdocPresentation(true, externalSid); // mdoc mit JWE verschlüsselt senden
  } else if (mode === '5') {
    console.log(`Beschreibung: Vollständige mDL E2E-Pipeline (mDL-Ausstellung + mdoc-Präsentation).`);
    const issuedCredential = await runIssuance('mso_mdoc', externalSid);
    if (externalSid && externalSid.startsWith('session_iss_')) {
      console.log(`🎉 Erfolgreich! mDL-Führerschein wurde via OpenID4VCI an Browser-Sitzung ausgestellt.`);
    } else {
      await runMdocPresentation(true, externalSid, issuedCredential);
    }
  } else {
    console.error(`${COLOR_ERROR}❌ Ungültiger Modus: ${mode}. Unterstützt werden: 1, 2, 3, 4, 5.${COLOR_RESET}`);
    process.exit(1);
  }

  printStatsTable();
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * SCHRITT A: AUSSTELLUNGS-PROZESS (OpenID4VCI) - Nur für Modus 3
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function runIssuance(format = 'dc+sd-jwt', externalSid = null) {
  console.log(`\n${COLOR_INFO}--- PHASE 1: DYNAMISCHE AUSWEIS-HERAUSGABE (OpenID4VCI) ---${COLOR_RESET}`);
  console.log(`   Format: ${COLOR_BOLD}${format}${COLOR_RESET}`);

  const keysPath = './demo-keys.json';
  if (!fs.existsSync(keysPath)) {
    console.error(`${COLOR_ERROR}❌ Fehler: Keine aktiven Demo-Schlüssel gefunden!${COLOR_RESET}`);
    console.error(`Bitte starten Sie zuerst den Express-Server v8/v9 mit:`);
    console.error(`   node eudi-verifier-server-v9.js`);
    process.exit(1);
  }

  console.log(`[VCI 1] Lade PKI-Schlüssel des Wallet-Providers...`);
  const demoKeys = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  console.log(`   ✔ Keys erfolgreich geladen.`);

  console.log(`[VCI 2] Generiere ephemere Wallet- und Device-Binding-Schlüssel (P-256)...`);
  const walletKeyPair = trackTime('Schlüsselgenerierung: Wallet (P-256)', () =>
    crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  );
  const deviceKeyPair = trackTime('Schlüsselgenerierung: Device-Binding (P-256)', () =>
    crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  );
  const walletPubKeyJwk = walletKeyPair.publicKey.export({ format: 'jwk' });
  const devicePubKeyJwk = deviceKeyPair.publicKey.export({ format: 'jwk' });

  let sessionId, wiaChallenge;
  if (externalSid && externalSid.startsWith('session_iss_')) {
    console.log(`[VCI 3] Verwende übergebene Browser-Ausstellungs-Sitzung: ${externalSid}`);
    sessionId = externalSid;
    const sessionInfo = await trackTime('HTTP: Hole VCI Session Info',
      fetch(`${API_BASE}/api/issuance/session-info?sid=${sessionId}`).then(res => res.json())
    );
    wiaChallenge = sessionInfo.wiaChallenge;
    console.log(`   ✔ Challenge erfolgreich abgerufen: ${wiaChallenge}`);
  } else {
    console.log(`[VCI 3] Initiiere neue Ausstellungs-Sitzung...`);
    const initResponse = await trackTime('HTTP: Initiere VCI Session',
      fetch(`${API_BASE}/api/issuance/initiate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: format })
      }).then(res => res.json())
    );
    sessionId = initResponse.sessionId;
    wiaChallenge = initResponse.wiaChallenge;
  }
  console.log(`   ✔ Session erstellt. ID: ${sessionId}`);

  console.log(`[VCI 4] Hole frische Einmal-Nonces vom Nonce-Endpoint...`);
  const nonceResponse = await trackTime('HTTP: Hole VCI Nonces',
    fetch(`${API_BASE}/api/issuance/nonce`, { method: 'POST' }).then(res => res.json())
  );

  console.log(`[VCI 5] Bereite Wallet Instance Attestation (WIA) & WIA-PoP vor (Säule 4)...`);
  const wiaToken = trackTime('Krypto: Signiere WIA JWT', () => {
    const header = { alg: 'ES256', typ: 'oauth-client-attestation+jwt' };
    const payload = {
      iss: 'https://wallet-provider.de',
      sub: 'https://wallet.example.com/instances/12345',
      cnf: { jwk: walletPubKeyJwk }
    };
    return signJws(header, payload, demoKeys.demoWalletKeys.privateKey);
  });

  const wiaPop = trackTime('Krypto: Signiere WIA-PoP JWT', () => {
    const header = { alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' };
    const payload = {
      iss: 'https://wallet-provider.de',
      aud: `${API_BASE}/api/issuance`,
      challenge: wiaChallenge
    };
    return signJws(header, payload, walletKeyPair.privateKey);
  });

  console.log(`[VCI 6] Erzeuge DPoP-Proof für Token-Endpoint (Sender-Constraint)...`);
  const tokenDpopProof = trackTime('Krypto: Signiere Token DPoP Proof', () => {
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletPubKeyJwk };
    const payload = {
      htm: 'POST',
      htu: `${API_BASE}/api/issuance/token`,
      nonce: nonceResponse.dpop_nonce
    };
    return signJws(header, payload, walletKeyPair.privateKey);
  });

  console.log(`[VCI 7] Sende Token-Exchange Anfrage...`);
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

  console.log(`[VCI 8] Bereite Belegnachweis (Device-Binding Proof) vor...`);
  const credNonces = await trackTime('HTTP: Hole VCI Credential Nonces',
    fetch(`${API_BASE}/api/issuance/nonce`, { method: 'POST' }).then(res => res.json())
  );

  const credDpopProof = trackTime('Krypto: Signiere Credential DPoP Proof', () => {
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletPubKeyJwk };
    const payload = {
      htm: 'POST',
      htu: `${API_BASE}/api/issuance/credential`,
      nonce: credNonces.dpop_nonce
    };
    return signJws(header, payload, walletKeyPair.privateKey);
  });

  const popProofJwt = trackTime('Krypto: Signiere Device-Binding PoP (c_nonce)', () => {
    const header = { alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: devicePubKeyJwk };
    const payload = {
      aud: `${API_BASE}/api/issuance`,
      nonce: credNonces.c_nonce
    };
    return signJws(header, payload, deviceKeyPair.privateKey);
  });

  console.log(`[VCI 9] Rufe frisch ausgestellten mdoc/SD-JWT Ausweis ab...`);
  const credRequestPayload = {
    credential_configuration_id: format === 'mso_mdoc' ? 'mDL_mso_mdoc' : 'PID_SD_JWT_VC',
    proofs: {
      jwt: popProofJwt
    }
  };

  const credResponse = await trackTime('HTTP: Ausweis abrufen (/credential)',
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
  console.log(`${COLOR_SUCCESS}✅ Ausweis erfolgreich ausgestellt! (Länge: ${issuedCredential.length} Zeichen)${COLOR_RESET}`);

  return {
    credential: issuedCredential,
    devicePrivateKey: deviceKeyPair.privateKey,
    devicePubKeyJwk: devicePubKeyJwk
  };
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * SCHRITT B: PRÄSENTATIONS-PROZESS (OpenID4VP) - Modi 1, 2 und 3
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function runPresentation(useEncryption, issuedData, externalSid = null) {
  console.log(`\n${COLOR_INFO}--- PHASE 2: AUSWEIS-PRÄSENTATION (OpenID4VP) ---${COLOR_RESET}`);

  let sessionId, requestUri;
  if (externalSid) {
    console.log(`[VP 1] Verwende übergebene Browser-Sitzungs-ID: ${externalSid}`);
    sessionId = externalSid;
    requestUri = `${API_BASE}/api/presentation/request-jwt?sid=${sessionId}`;
  } else {
    console.log(`[VP 1] Initiiere neue Präsentations-Sitzung am Verifizierer...`);
    const initResponse = await trackTime('HTTP: Initiere VP Session',
      fetch(`${API_BASE}/api/presentation/initiate`).then(res => res.json())
    );
    sessionId = initResponse.sessionId;
    const qrCodeUrl = initResponse.qrCodeUrl;
    console.log(`   ✔ Session erfolgreich erstellt. ID: ${sessionId}`);
    requestUri = new URL(qrCodeUrl).searchParams.get('request_uri');
  }

  console.log(`[VP 2] Rufe Request Object (JAR) via request_uri ab...`);
  const signedJar = await trackTime('HTTP: Hole JAR Request',
    fetch(requestUri).then(res => res.text())
  );

  const jarPayloadB64 = signedJar.split('.')[1];
  const jarPayload = JSON.parse(Buffer.from(jarPayloadB64, 'base64url').toString('utf8'));
  const nonce = jarPayload.nonce;
  const rpKeyJwk = jarPayload.client_metadata?.jwks?.keys[0];

  console.log(`   ✔ JAR erfolgreich empfangen und demaskiert.`);
  console.log(`   ✔ Extrahierte Präsentations-Nonce: ${nonce}`);

  console.log(`[VP 3] Bereite Präsentations-Payload (SD-JWT VC + Key Binding) vor...`);
  let finalSdJwt;
  let presentationDevicePrivateKey;

  if (issuedData) {
    console.log(`   👉 Nutze dynamisch ausgestellten Ausweis aus Phase 1.`);
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

    const kbJwt = trackTime('Krypto: Signiere Key-Binding (KB-JWT)', () =>
      signJws(kbHeader, kbPayload, presentationDevicePrivateKey)
    );

    finalSdJwt = `${issuerJwt}~${disclosures.join('~')}~${kbJwt}`;
  } else {
    console.log(`   👉 Nutze statisch signierten Mock-Ausweis für Erika Mustermann.`);
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
    console.log(`[VP 4] Verschlüssele Präsentation via JWE (ECDH-ES + AES-128-GCM)...`);

    const walletEncKeyPair = trackTime('Schlüsselgenerierung: Ephemerer VP-Key (P-256)', () =>
      crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    );
    const walletEncPubKeyJwk = walletEncKeyPair.publicKey.export({ format: 'jwk' });

    const rpPublicKey = crypto.createPublicKey({ key: rpKeyJwk, format: 'jwk' });
    const sharedSecret = trackTime('Krypto: ECDH Key Agreement', () =>
      crypto.diffieHellman({
        privateKey: walletEncKeyPair.privateKey,
        publicKey: rpPublicKey
      })
    );

    const cek = trackTime('Krypto: Concat KDF Key Derivation', () =>
      deriveConcatKDF(sharedSecret, 16, 'A128GCM')
    );

    const jweString = trackTime('Krypto: AES-128-GCM JWE Verschlüsselung', () => {
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

    console.log(`   ✔ JWE-Verschlüsselung abgeschlossen. JWE: ${jweString.substring(0, 50)}...`);
    postBodyString = `response=${encodeURIComponent(jweString)}&state=${encodeURIComponent(sessionId)}`;
  } else {
    console.log(`[VP 4] Sende unverschlüsselte Payload (Fallback-Kanal direct_post)...`);
    postBodyString = `vp_token=${encodeURIComponent(JSON.stringify(cleartextPayload.vp_token))}&wia_token=${encodeURIComponent(cleartextPayload.wia_token)}&state=${encodeURIComponent(sessionId)}`;
  }

  console.log(`[VP 5] Übermittle direct_post Callback an den RP-Server...`);
  const callbackResponse = await trackTime('HTTP: direct_post Callback übermitteln',
    fetch(`${API_BASE}/api/presentation/callback`, {
      method: 'POST',
      headers: { 'Content-Type': postContentType },
      body: postBodyString
    }).then(res => res.json())
  );
  console.log(`   ✔ Server meldet Redirect-URI: ${callbackResponse.redirect_uri}`);

  console.log(`[VP 6] Frage finalen Verifizierungsstatus im Server ab...`);
  const statusResponse = await trackTime('HTTP: Polling Onboarding Status',
    fetch(`${API_BASE}/api/presentation/status?sid=${sessionId}`).then(res => res.json())
  );

  console.log(`\n${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`${COLOR_BOLD}${COLOR_SUCCESS}🎯 STATUS DER PRÄSENTATIONS-VERIFIKATION: ${statusResponse.status}${COLOR_RESET}`);
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`Transport-Verschlüsselung (JWE): ${COLOR_BOLD}${statusResponse.isEncrypted ? 'JA 🔒 (direct_post.jwt)' : 'NEIN ⚠️ (Klartext direct_post)'}${COLOR_RESET}`);
  console.log(`Übertragene Claims:`);
  console.log(JSON.stringify(statusResponse.claims, null, 2));
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}\n`);
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * SCHRITT C: MDOC PRÄSENTATIONS-PROZESS (MODUS 4)
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function runMdocPresentation(useEncryption, externalSid = null, issuedData = null) {
  console.log(`\n${COLOR_INFO}--- AUSWEIS-PRÄSENTATION IM ISO MDOC-FORMAT (mDL) ---${COLOR_RESET}`);

  let sessionId, requestUri;
  if (externalSid) {
    console.log(`[mdoc 1] Verwende übergebene Browser-Sitzungs-ID: ${externalSid}`);
    sessionId = externalSid;
    requestUri = `${API_BASE}/api/presentation/request-jwt?sid=${sessionId}`;
  } else {
    console.log(`[mdoc 1] Initiiere neue Präsentations-Sitzung am Verifizierer...`);
    const initResponse = await trackTime('HTTP: Initiere mdoc Session',
      fetch(`${API_BASE}/api/presentation/initiate`).then(res => res.json())
    );
    sessionId = initResponse.sessionId;
    const qrCodeUrl = initResponse.qrCodeUrl;
    console.log(`   ✔ Session erfolgreich erstellt. ID: ${sessionId}`);
    requestUri = new URL(qrCodeUrl).searchParams.get('request_uri');
  }

  console.log(`[mdoc 2] Rufe Request Object (JAR) via request_uri ab...`);
  const signedJar = await trackTime('HTTP: Hole JAR Request',
    fetch(requestUri).then(res => res.text())
  );

  const jarPayloadB64 = signedJar.split('.')[1];
  const jarPayload = JSON.parse(Buffer.from(jarPayloadB64, 'base64url').toString('utf8'));
  const nonce = jarPayload.nonce;
  const rpKeyJwk = jarPayload.client_metadata?.jwks?.keys[0];

  console.log(`   ✔ Extrahierte Präsentations-Nonce: ${nonce}`);

  console.log(`[mdoc 3] Erzeuge mathematisch korrektes SessionTranscript (ISO 18013-5)...`);

  // 1. HandoverInfo-Struktur aufbauen und CBOR-kodieren
  const rpClientId = "x509_san_dns:client.example.org";
  const responseUri = `${API_BASE}/api/presentation/callback`;

  let jwkThumbprint = null;
  if (useEncryption && rpKeyJwk) {
    jwkThumbprint = trackTime('Krypto: Berechne JWK Thumbprint (RFC 7638)', () => getJwkThumbprint(rpKeyJwk));
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

  const sessionTranscriptCbor = trackTime('CBOR: Kodiere SessionTranscript', () => encodeCBOR(sessionTranscript));
  console.log(`   ✔ SessionTranscript CBOR generiert (${sessionTranscriptCbor.length} Bytes).`);

  // 2. Erzeuge Erikas mdoc DeviceResponse CBOR-Dokument
  console.log(`[mdoc 4] Erzeuge mdoc-Dokument und signiere Gerätebindung...`);

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

  // Callback payload zusammenbauen
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
    console.log(`[mdoc 5] Verschlüssele mdoc via JWE (ECDH-ES + AES-128-GCM)...`);

    const walletEncKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const walletEncPubKeyJwk = walletEncKeyPair.publicKey.export({ format: 'jwk' });

    const rpPublicKey = crypto.createPublicKey({ key: rpKeyJwk, format: 'jwk' });
    const sharedSecret = crypto.diffieHellman({
      privateKey: walletEncKeyPair.privateKey,
      publicKey: rpPublicKey
    });

    const cek = deriveConcatKDF(sharedSecret, 16, 'A128GCM');

    const jweString = trackTime('Krypto: AES-128-GCM JWE Verschlüsselung', () => {
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

  console.log(`[mdoc 6] Übermittle direct_post.jwt Callback an den RP-Server...`);
  const callbackResponse = await trackTime('HTTP: direct_post Callback übermitteln',
    fetch(`${API_BASE}/api/presentation/callback`, {
      method: 'POST',
      headers: { 'Content-Type': postContentType },
      body: postBodyString
    }).then(res => res.json())
  );
  console.log(`   ✔ Server meldet Redirect-URI: ${callbackResponse.redirect_uri}`);

  console.log(`[mdoc 7] Frage finalen Verifizierungsstatus im Server ab...`);
  const statusResponse = await trackTime('HTTP: Polling Onboarding Status',
    fetch(`${API_BASE}/api/presentation/status?sid=${sessionId}`).then(res => res.json())
  );

  console.log(`\n${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`${COLOR_BOLD}${COLOR_SUCCESS}🎯 STATUS DER PRÄSENTATIONS-VERIFIKATION: ${statusResponse.status}${COLOR_RESET}`);
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}`);
  console.log(`Präsentiertes Format:             ${COLOR_BOLD}ISO mdoc (mDL)${COLOR_RESET}`);
  console.log(`Transport-Verschlüsselung (JWE):  ${COLOR_BOLD}${statusResponse.isEncrypted ? 'JA 🔒 (direct_post.jwt)' : 'NEIN ⚠️ (Klartext direct_post)'}${COLOR_RESET}`);
  console.log(`Übertragene Führerschein-Claims:`);
  console.log(JSON.stringify(statusResponse.claims, null, 2));
  console.log(`${COLOR_CYAN}================================================================${COLOR_RESET}\n`);
}

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * PRINT STATS TABLE (Kryptografische & Netzwerk Performance-Auswertung)
 * ─────────────────────────────────────────────────────────────────────────────
 */
function printStatsTable() {
  console.log(`${COLOR_BOLD}${COLOR_CYAN}📊 KONSOLIDIERTE LAUFZEIT-STATISTIK DER TRANSAKTION${COLOR_RESET}`);

  const col1Width = 55;
  const col2Width = 14;

  console.log(`+-${'-'.repeat(col1Width)}-+-${'-'.repeat(col2Width)}-+`);
  console.log(`| ${COLOR_BOLD}${'Aktion / Kryptografischer Schritt'.padEnd(col1Width)}${COLOR_RESET} | ${COLOR_BOLD}${'Laufzeit'.padEnd(col2Width)}${COLOR_RESET} |`);
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
  console.log(`| ${COLOR_BOLD}${'GESAMT-DURCHLAUFZEIT (Simulator)'.padEnd(col1Width)}${COLOR_RESET} | ${COLOR_BOLD}${COLOR_SUCCESS}${totalTimeStr}${COLOR_RESET}${totalPadding} |`);
  console.log(`+-${'-'.repeat(col1Width)}-+-${'-'.repeat(col2Width)}-+`);
}

run().catch(err => {
  console.error(`\n${COLOR_ERROR}❌ Fataler Fehler im Test-Harness:${COLOR_RESET}`, err);
  process.exit(1);
});
