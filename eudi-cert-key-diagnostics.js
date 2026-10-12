const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function runDiagnostics() {
  console.log('================================================================');
  console.log('  EUDI WALLET - CERTIFICATE & PRIVATE KEY DIAGNOSTIC TOOL       ');
  console.log('================================================================\n');

  const certsDir = path.join(process.cwd(), '.', 'certs');
  console.log(`-> Searching for certificate & key files in: ${certsDir}\n`);

  // 1. Locate Access Certificate
  let certPath = null;
  const certCandidates = ['access_certificate.pem', 'access_certificate.cer', 'access_certificate.der'];
  for (const candidate of certCandidates) {
    const p = path.join(certsDir, candidate);
    if (fs.existsSync(p)) {
      certPath = p;
      break;
    }
  }

  // 2. Locate Private Key
  let keyPath = null;
  const keyCandidates = ['access_certificate_key.pem', 'access_key.pem', 'private_key.pem'];
  for (const candidate of keyCandidates) {
    const p = path.join(certsDir, candidate);
    if (fs.existsSync(p)) {
      keyPath = p;
      break;
    }
  }

  if (!certPath) {
    console.error('❌ [ERROR] Access Certificate file not found in ./certs/');
    console.error('   Expected one of: access_certificate.pem, access_certificate.cer, access_certificate.der');
    console.log('-> Generating mock keypair for diagnostic demonstration...\n');
  } else {
    console.log(`✓ [PASS] Access Certificate found: ${path.basename(certPath)}`);
  }

  if (!keyPath) {
    console.error('❌ [ERROR] Private Key file not found in ./certs/');
    console.error('   Expected one of: access_certificate_key.pem, access_key.pem, private_key.pem');
  } else {
    console.log(`✓ [PASS] Private Key found: ${path.basename(keyPath)}`);
  }

  let certBuf, keyPem;

  if (certPath && keyPath) {
    certBuf = fs.readFileSync(certPath);
    keyPem = fs.readFileSync(keyPath, 'utf8');
  } else {
    console.log('--- DEMO / DIAGNOSTIC SYNTHESIS MODE ---');
    const demoPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    keyPem = demoPair.privateKey.export({ type: 'sec1', format: 'pem' });

    // Create self-signed cert in memory or generate key pair match test
    console.log('Testing diagnostic routine with generated P-256 keypair...\n');
  }

  console.log('----------------------------------------------------------------');
  console.log(' [TEST 1] X.509 Certificate Parsing & Metadata Check');
  console.log('----------------------------------------------------------------');

  let x509, publicKeyObj;
  try {
    if (certBuf) {
      x509 = new crypto.X509Certificate(certBuf);
      console.log(`  [PASS] Successfully parsed X.509 Certificate`);
      console.log(`         Subject : ${x509.subject}`);
      console.log(`         Issuer  : ${x509.issuer}`);
      console.log(`         Valid   : From ${x509.validFrom} To ${x509.validTo}`);

      const now = new Date();
      if (now < new Date(x509.validFrom) || now > new Date(x509.validTo)) {
        console.warn(`  ⚠️  [WARN] Certificate is EXPIRED or NOT YET VALID!`);
      } else {
        console.log(`  [PASS] Certificate validity period is currently ACTIVE`);
      }

      publicKeyObj = x509.publicKey;
      const keyDetail = publicKeyObj.asymmetricKeyType;
      console.log(`  [PASS] Public Key Asymmetric Type: ${keyDetail.toUpperCase()}`);
    } else {
      console.log('  [SKIP] No cert file supplied, skipping X.509 metadata check.');
    }
  } catch (err) {
    console.error(`  ❌ [ERROR] Could not parse X.509 Certificate: ${err.message}`);
  }

  console.log('\n----------------------------------------------------------------');
  console.log(' [TEST 2] Private Key Parsing & Key Details');
  console.log('----------------------------------------------------------------');

  let privateKeyObj;
  try {
    privateKeyObj = crypto.createPrivateKey(keyPem);
    console.log(`  [PASS] Successfully parsed Private Key`);
    console.log(`         Type: ${privateKeyObj.asymmetricKeyType.toUpperCase()}`);

    if (privateKeyObj.asymmetricKeyDetails) {
      console.log(`         Details: ${JSON.stringify(privateKeyObj.asymmetricKeyDetails)}`);
    }
  } catch (err) {
    console.error(`  ❌ [FAIL] Could not parse Private Key: ${err.message}`);
    return;
  }

  console.log('\n----------------------------------------------------------------');
  console.log(' [TEST 3] Cryptographic Key-Pair Match Check (CRITICAL)');
  console.log('----------------------------------------------------------------');

  if (publicKeyObj && privateKeyObj) {
    const testPayload = Buffer.from('EUDI_WALLET_KEY_PAIR_VALIDATION_TEST_PAYLOAD_' + Date.now());

    // Test 3a: ES256 IEEE P1363 Signature
    try {
      const sigP1363 = crypto.sign('SHA256', testPayload, {
        key: privateKeyObj,
        dsaEncoding: 'ieee-p1363'
      });

      const validP1363 = crypto.verify('SHA256', testPayload, {
        key: publicKeyObj,
        dsaEncoding: 'ieee-p1363'
      }, sigP1363);

      if (validP1363) {
        console.log('  ✅ [MATCH CONFIRMED] Private Key MATS EXACTLY with the Public Key in the Certificate!');
        console.log('     -> JWS ES256 IEEE P1363 signature verification: SUCCESS');
      } else {
        console.error('  ❌ [MISMATCH ERROR] Private Key DOES NOT MATCH the Certificate!');
        console.error('     -> The private key used for JAR signing is NOT the key inside the X.509 Certificate.');
        console.error('     -> The Wallet App WILL reject the signature with: "Unable to verify signature using public key from leaf certificate"');
      }
    } catch (err) {
      console.error(`  ❌ [ERROR] Signature generation/verification error: ${err.message}`);
    }

    // Test 3b: ASN.1 DER vs IEEE P1363 Encoding Check
    console.log('\n  [INFO] Checking Signature Encodings (IEEE P1363 vs ASN.1 DER):');
    try {
      const sigDer = crypto.sign('SHA256', testPayload, { key: privateKeyObj });
      const sigP1363 = crypto.sign('SHA256', testPayload, { key: privateKeyObj, dsaEncoding: 'ieee-p1363' });

      console.log(`         ASN.1 DER Signature Length  : ${sigDer.length} bytes`);
      console.log(`         IEEE P1363 Signature Length: ${sigP1363.length} bytes (Must be exactly 64 bytes for ES256 JWS)`);

      if (sigP1363.length === 64) {
        console.log('  [PASS] IEEE P1363 encoding correctly formatted (64 bytes).');
      } else {
        console.warn('  ⚠️  [WARN] Unexpected IEEE P1363 signature length.');
      }
    } catch (err) {
      console.error(`  [FAIL] Encoding check failed: ${err.message}`);
    }
  } else {
    console.log('  [SKIP] Skipping keypair match test because either cert or key is missing.');
  }

  console.log('\n----------------------------------------------------------------');
  console.log(' [TEST 4] HAIP client_id Hash Calculation (x509_hash)');
  console.log('----------------------------------------------------------------');

  if (x509) {
    const rawDer = x509.raw;
    const sha256Hash = crypto.createHash('sha256').update(rawDer).digest();
    const clientId = `x509_hash:${sha256Hash.toString('base64url')}`;

    console.log(`  [PASS] DER Raw Length : ${rawDer.length} bytes`);
    console.log(`  [PASS] HAIP client_id : ${clientId}`);
  } else {
    console.log('  [SKIP] No certificate loaded.');
  }

  console.log('\n================================================================');
  console.log('  DIAGNOSTIC SUMMARY & NEXT STEPS                               ');
  console.log('================================================================');
  console.log('If TEST 3 failed: Replace access_certificate_key.pem with the matching private key.');
  console.log('If TEST 3 passed: Ensure your server code sets dsaEncoding: "ieee-p1363" when signing!');
  console.log('================================================================\n');
}

runDiagnostics();
