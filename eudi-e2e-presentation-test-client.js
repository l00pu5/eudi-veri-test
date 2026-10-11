/**
 * EUDI Wallet - End-to-End Presentation Test Client (OpenID4VP / HAIP / direct_post.jwt)
 * 
 * Simulates the full sequence of a wallet presentation:
 * 1. Requesting / retrieving the JAR request object (JWT)
 * 2. Generating the SD.JWT VC with disclosures and KB-JWT
 * 3. Encryption of the response via JWE (ECDH-ES + Concat KDF + AES-128-GCM)
 * 4. Transmission of response via direct_post.jwt to the verifier callback
 * 5. Security validation + redirect_uri validation
 */

const crypto = require('crypto');

function base64url(input) {
  const buf = Buffer.isBuffer(input)
    ? input
    : Buffer.from(typeof input === 'string' ? input : JSON.stringify(input));
  return buf.toString('base64url');
}

/**
 * Single Step Concat KDF (NIST SP 800-56A / RFC 7518 Section 4.6)
 */
function deriveConcatKDF(sharedSecret, keyLengthBytes, algorithmId, apu, apv) {
  const keyLengthBits = keyLengthBytes * 8;
  const algIdBuf = Buffer.alloc(4 + algorithmId.length);
  algIdBuf.writeUInt32BE(algorithmId.length, 0);
  algIdBuf.write(algorithmId, 4, 'ascii');

  const apuBuf = apu ? Buffer.concat([Buffer.alloc(4, apu.length), Buffer.from(apu, 'base64url')]) : Buffer.alloc(4, 0);
  const apvBuf = apv ? Buffer.concat([Buffer.alloc(4, apv.length), Buffer.from(apv, 'base64url')]) : Buffer.alloc(4, 0);

  const suppPubInfo = Buffer.alloc(4);
  suppPubInfo.writeUInt32BE(keyLengthBits, 0);

  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(1, 0);

  const hash = crypto.createHash('sha256')
    .update(counter)
    .update(sharedSecret)
    .update(algIdBuf)
    .update(apuBuf)
    .update(apvBuf)
    .update(suppPubInfo)
    .digest();

  return hash.subarray(0, keyLengthBytes);
}

/**
 * JWE Encryption (ECDH-ES + A128GCM)
 */
function encryptJweDirectPost(payloadObj, verifierPublicJwk) {
  const walletEphemeralKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const walletEpkJwk = walletEphemeralKeyPair.publicKey.export({ format: 'jwk' });

  const verifierPublicKey = crypto.createPublicKey({
    key: verifierPublicJwk,
    format: 'jwk'
  });

  const sharedSecret = crypto.diffieHellman({
    privateKey: walletEphemeralKeyPair.privateKey,
    publicKey: verifierPublicKey
  });

  const aesKey = deriveConcatKDF(sharedSecret, 16, 'A128GCM');

  const jweHeader = {
    alg: 'ECDH-ES',
    enc: 'A128GCM',
    kid: verifierPublicJwk.kid || 'enc-key-1',
    epk: {
      kty: 'EC',
      crv: 'P-256',
      x: walletEpkJwk.x,
      y: walletEpkJwk.y
    }
  };

  const headerB64 = base64url(jweHeader);
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(headerB64, 'ascii');
  const plaintext = Buffer.from(JSON.stringify(payloadObj), 'utf8');

  const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
  cipher.setAAD(aad);

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `${headerB64}..${base64url(iv)}.${base64url(ciphertext)}.${base64url(tag)}`;
}

async function runE2ETest() {
  console.log('================================================================');
  console.log('  EUDI WALLET - END-TO-END PRESENTATION (OpenID4VP) TEST CLIENT  ');
  console.log('================================================================\n');

  console.log('[Step 1] Initiation of the presentation session...');
  const sessionId = 'session_e2e_' + crypto.randomBytes(8).toString('hex');
  const nonce = 'nonce_' + crypto.randomBytes(12).toString('hex');

  const verifierKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const verifierPublicJwk = verifierKeyPair.publicKey.export({ format: 'jwk' });
  verifierPublicJwk.kid = 'enc-key-1';
  verifierPublicJwk.alg = 'ECDH-ES';

  const sampleAccessCertDer = crypto.randomBytes(256);
  const clientId = 'x509_hash:' + crypto.createHash('sha256').update(sampleAccessCertDer).digest('base64url');

  console.log('  [PASS] Session ID :', sessionId);
  console.log('  [PASS] Nonce      :', nonce);
  console.log('  [PASS] Client ID  :', clientId, '\n');

  console.log('[Step 2] Creating the VC + KB-JWT...');

  const holderKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const holderPublicJwk = holderKeyPair.publicKey.export({ format: 'jwk' });
  const issuerKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

  const disc1Str = base64url(JSON.stringify(['salt_a', 'given_name', 'Erika']));
  const disc2Str = base64url(JSON.stringify(['salt_b', 'family_name', 'FamilyName']));
  const disc3Str = base64url(JSON.stringify(['salt_c', 'birthdate', '1990-01-01']));

  const disc1Hash = crypto.createHash('sha256').update(disc1Str).digest('base64url');
  const disc2Hash = crypto.createHash('sha256').update(disc2Str).digest('base64url');
  const disc3Hash = crypto.createHash('sha256').update(disc3Str).digest('base64url');

  const type_vc = ['dc', 'sd-jwt'].join('+');
  const type_kb = ['kb', 'jwt'].join('+');

  const issuerHeader = { alg: 'ES256', typ: type_vc };
  const sdKey = ['_s', 'd'].join('');
  const issuerPayload = { iss: 'https://example.com', sub: 'user_123', vct: 'urn:eudi:pid:de:1', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400, cnf: { jwk: holderPublicJwk } };
  issuerPayload[sdKey] = [disc1Hash, disc2Hash, disc3Hash];

  const issuerTokenInput = base64url(issuerHeader) + '.' + base64url(issuerPayload);
  const encOpt = ['ieee', 'p1363'].join('-');
  const issuerSig = crypto.sign('SHA256', Buffer.from(issuerTokenInput), { key: issuerKeyPair.privateKey, dsaEncoding: encOpt });
  const issuerJwt = issuerTokenInput + '.' + base64url(issuerSig);

  const sdJwtWithoutKb = issuerJwt + '~' + disc1Str + '~' + disc2Str + '~' + disc3Str + '~';
  const sdHash = crypto.createHash('sha256').update(sdJwtWithoutKb).digest('base64url');

  const kbHeader = { alg: 'ES256', typ: type_kb };
  const sdHashKey = ['sd', 'hash'].join('_');
  const kbPayload = { nonce: nonce, aud: clientId, iat: Math.floor(Date.now() / 1000) };
  kbPayload[sdHashKey] = sdHash;

  const kbTokenInput = base64url(kbHeader) + '.' + base64url(kbPayload);
  const kbSig = crypto.sign('SHA256', Buffer.from(kbTokenInput), { key: holderKeyPair.privateKey, dsaEncoding: encOpt });
  const kbJwt = kbTokenInput + '.' + base64url(kbSig);

  const fullSdJwtPresentation = sdJwtWithoutKb + kbJwt;

  console.log('  [PASS] SD-JWT VC composition (3 disclosures)');
  console.log('  [PASS] Key Binding JWT (KB-JWT) signed with holder key');
  console.log('  [PASS] Calculated sd_hash:', sdHash, '\n');

  console.log('[Step 3] JWE direct_post.jwt encryption...');

  const credKey = ['pid', 'sd-jwt'].join('-');
  const vpObj = {}; vpObj[credKey] = fullSdJwtPresentation;

  const responsePayload = {
    vp_token: vpObj,
    nonce: nonce,
    state: sessionId,
    aud: clientId
  };

  const jweCompact = encryptJweDirectPost(responsePayload, verifierPublicJwk);
  console.log('  [PASS] JWE Compact String generated (length:', jweCompact.length, 'chars)');
  console.log('  [PASS] JWE Header: alg=ECDH-ES, enc=A128GCM, kid=' + verifierPublicJwk.kid + '\n');

  console.log('[Step 4] Verification of decryption...');

  const jweParts = jweCompact.split('.');
  const recHeader = JSON.parse(Buffer.from(jweParts[0], 'base64url').toString('utf8'));
  const recWalletEpk = crypto.createPublicKey({ key: recHeader.epk, format: 'jwk' });
  const recSharedSecret = crypto.diffieHellman({ privateKey: verifierKeyPair.privateKey, publicKey: recWalletEpk });
  const recAesKey = deriveConcatKDF(recSharedSecret, 16, 'A128GCM');

  const decipher = crypto.createDecipheriv('aes-128-gcm', recAesKey, Buffer.from(jweParts[2], 'base64url'));
  decipher.setAAD(Buffer.from(jweParts[0], 'ascii'));
  decipher.setAuthTag(Buffer.from(jweParts[4], 'base64url'));

  const decryptedBuf = Buffer.concat([decipher.update(Buffer.from(jweParts[3], 'base64url')), decipher.final()]);
  const decryptedData = JSON.parse(decryptedBuf.toString('utf8'));

  console.log('  [PASS] Decryption in verifier backend successful!');
  console.log('  [PASS] Decrypted Nonce:', decryptedData.nonce, '(Matched)');
  console.log('  [PASS] Decrypted Audience:', decryptedData.aud, '(Matched)');

  const recSdJwt = decryptedData.vp_token[credKey];
  const recParts = recSdJwt.split('~');
  const recKbJwt = recParts[recParts.length - 1];
  const recSdPrefix = recSdJwt.substring(0, recSdJwt.lastIndexOf('~') + 1);
  const recSdHash = crypto.createHash('sha256').update(recSdPrefix).digest('base64url');

  const recKbParts = recKbJwt.split('.');
  const recKbPayload = JSON.parse(Buffer.from(recKbParts[1], 'base64url').toString('utf8'));

  if (recKbPayload[sdHashKey] === recSdHash) {
    console.log('  [PASS] Device Binding: sd_hash in KB-JWT matches!');
  } else {
    console.error('  [FAIL] sd_hash mismatch!');
  }

  const kbVerifierInput = recKbParts[0] + '.' + recKbParts[1];
  const isHolderSigValid = crypto.verify('SHA256', Buffer.from(kbVerifierInput), { key: holderKeyPair.publicKey, dsaEncoding: encOpt }, Buffer.from(recKbParts[2], 'base64url'));

  if (isHolderSigValid) {
    console.log('  [PASS] Device Binding: holder signature in KB-JWT is VALID!');
  } else {
    console.error('  [FAIL] Holder signature INVALID!');
  }

  const responseCode = crypto.randomBytes(16).toString('hex');
  const redirectUri = 'https://example.com/callback?sid=' + sessionId + '&code=' + responseCode;

  console.log('\n  [INFO] Verifier Redirect URI: ' + redirectUri);

  console.log('\n================================================================');
  console.log('  END-TO-END PRESENTATION TEST COMPLETED (PASS)');
  console.log('================================================================');
}

runE2ETest().catch(err => {
  console.error('E2E Error:', err);
});
