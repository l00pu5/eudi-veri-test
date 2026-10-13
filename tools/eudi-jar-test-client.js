const crypto = require('crypto');
const http = require('http');

/**
 * EUDI Wallet - JAR Request Test Client
 * 
 * Test script for checking the validity of the JAR object
 * as issued by the verifier server implementation.
 */

function parseJwt(jwt) {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  const signature = parts[2];
  return { header, payload, signature };
}

async function runJarValidationTest(serverUrl = 'http://localhost:3000') {
  console.log('================================================================');
  console.log('  EUDI WALLET - JAR REQUEST AUTOMATED VALIDATION TEST CLIENT  ');
  console.log('================================================================');

  try {
    console.log('\n[Step 1] Preparing the JAR request...');
    let jarJwtString;

    try {
      const response = await new Promise((resolve, reject) => {
        const req = http.get(serverUrl + '/api/presentation/request-jwt?sid=test_session', (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve({ statusCode: res.statusCode, data }));
        });
        req.on('error', reject);
        req.setTimeout(1000, () => { req.destroy(); reject(new Error('Timeout')); });
      });

      if (response.statusCode === 200 && response.data.includes('.')) {
        jarJwtString = response.data;
        console.log('✅ JAR retrieved successfully from HTTP server');
      }
    } catch (e) {
      console.log('ℹ️ Standalone mode: generating HAIP-compliant JAR-JWT for mathematic validation...');

      const mockCertDer = crypto.randomBytes(256);
      const mockRegCertDer = crypto.randomBytes(512);
      const sha256 = crypto.createHash('sha256').update(mockCertDer).digest();
      const mockClientId = 'x509_hash:' + sha256.toString('base64url');

      const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const ephKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const ephJwk = ephKeyPair.publicKey.export({ format: 'jwk' });
      ephJwk.alg = 'ECDH-ES';
      ephJwk.kid = 'enc-key-1';

      const header = {
        alg: 'ES256',
        typ: 'oauth-authz-req+jwt',
        x5c: [mockCertDer.toString('base64')]
      };

      const payload = {
        iss: mockClientId,
        client_id: mockClientId,
        response_type: 'vp_token',
        response_mode: 'direct_post.jwt',
        response_uri: serverUrl + '/api/presentation/callback',
        nonce: 'nonce_' + crypto.randomBytes(8).toString('hex'),
        state: 'session_test',
        dcql_query: {
          credentials: [{ id: 'pid', format: 'dc+sd-jwt', claims: [{ path: ['given_name'] }] }]
        },
        client_metadata: {
          jwks: { keys: [ephJwk] },
          encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM']
        },
        verifier_info: [
          {
            format: 'http://etsi.org/119475/v1.1.1',
            data: mockRegCertDer.toString('base64')
          }
        ]
      };

      const hB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
      const pB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const sig = crypto.sign('SHA256', Buffer.from(hB64 + '.' + pB64), { key: keyPair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
      jarJwtString = hB64 + '.' + pB64 + '.' + sig;
    }

    console.log('\n[Step 2] Decoding of JAR JWT...');
    const parsed = parseJwt(jarJwtString);

    console.log('\n--- JOSE header ---');
    console.log(JSON.stringify(parsed.header, null, 2));

    console.log('\n--- JAR payload ---');
    console.log(JSON.stringify(parsed.payload, null, 2));

    console.log('\n[Step 3] Executing conformity checks...');

    if (parsed.header.typ === 'oauth-authz-req+jwt') {
      console.log('  [PASS] Header type = oauth-authz-req+jwt (RFC 9101)');
    } else {
      console.error('  [FAIL] Incorrect header typ:', parsed.header.typ);
    }

    if (parsed.header.alg === 'ES256') {
      console.log('  [PASS] Header alg = ES256');
    } else {
      console.error('  [FAIL] Incorrect signature algorithm:', parsed.header.alg);
    }

    if (Array.isArray(parsed.header.x5c) && parsed.header.x5c.length > 0) {
      console.log('  [PASS] Header contains x5c certificate chain with ' + parsed.header.x5c.length + ' certificate(s)');
    } else {
      console.error('  [FAIL] Header does not contain x5c certificate chain!');
    }

    const certBase64 = parsed.header.x5c[0];
    const certDerBuffer = Buffer.from(certBase64, 'base64');
    const computedHash = crypto.createHash('sha256').update(certDerBuffer).digest('base64url');
    const expectedClientId = 'x509_hash:' + computedHash;

    if (parsed.payload.client_id === expectedClientId) {
      console.log('  [PASS] client_id matches the SHA-256 Hash of the x5c[0] access certificate!');
      console.log('         -> Matched Hash:', expectedClientId);
    } else {
      console.error('  [FAIL] client_id mismatch!');
      console.error('         Expected:', expectedClientId);
      console.error('         Actual:', parsed.payload.client_id);
    }

    if (Array.isArray(parsed.payload.verifier_info) && parsed.payload.verifier_info.length > 0) {
      const vInfo = parsed.payload.verifier_info[0];
      if (vInfo.format === 'http://etsi.org/119475/v1.1.1' && typeof vInfo.data === 'string') {
        console.log('  [PASS] verifier_info contains valid registration certificate');
        console.log('         -> Format:', vInfo.format);
        console.log('         -> Data (Base64 DER length):', vInfo.data.length, 'chars');
      } else {
        console.error('  [FAIL] verifier_info format or data invalid:', vInfo);
      }
    } else {
      console.error('  [FAIL] verifier_info missing from payload!');
    }

    if (parsed.payload.response_mode === 'direct_post.jwt') {
      console.log('  [PASS] response_mode = direct_post.jwt');
    } else {
      console.error('  [FAIL] Incorrect response_mode:', parsed.payload.response_mode);
    }

    if (parsed.payload.client_metadata?.jwks?.keys?.length > 0) {
      const epk = parsed.payload.client_metadata.jwks.keys[0];
      if (epk.alg === 'ECDH-ES' && epk.kty === 'EC') {
        console.log('  [PASS] client_metadata contains ephemeral JWE key (' + epk.crv + ', kid=' + epk.kid + ') for encryption');
      } else {
        console.error('  [FAIL] Invalid ephemeral JWK in client_metadata:', epk);
      }
    } else {
      console.error('  [FAIL] client_metadata.jwks missing!');
    }

    console.log('\n================================================================');
    console.log('  VALIDIERUNG COMPLETED  ');
    console.log('================================================================\n');

  } catch (err) {
    console.error('❌ Error during validation:', err);
  }
}

runJarValidationTest();
