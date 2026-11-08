/**
 * EUDI Wallet - AKI Extractor Tool
 * 
 * Extracts and converts the Authority Key Identifier (AKI) or 
 * Subject Key Identifier (SKI) of an X.509 cert to base64url
 * 
 * Usage:
 *   node aki-extractor.js <CERT_PATH>
 *   node aki-extractor.js --cert certs/issuer_ca_cert.pem
 *   node aki-extractor.js certs/issuer_ca_cert.pem --verbose
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const crypto = require('crypto');

function parseArgs() {
  const args = process.argv.slice(2);
  let certPath = null;
  let verbose = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--verbose' || arg === '-v') {
      verbose = true;
    } else if (arg === '--cert' || arg === '-c') {
      certPath = args[++i];
    } else if (!arg.startsWith('-') && !certPath) {
      certPath = arg;
    }
  }

  return { certPath, verbose };
}

function extractAkiBase64Url(certPath, verbose) {
  if (!certPath) {
    if (verbose) {
      console.error('❌ no certificate path provided');
    } else {
      console.error('Usage: node aki-extractor.js <CERT_PATH>');
    }
    process.exit(1);
  }

  const resolvedPath = path.resolve(process.cwd(), certPath);
  if (!fs.existsSync(resolvedPath)) {
    console.error(`❌ file not found: ${certPath}`);
    process.exit(1);
  }

  let hexKeyId = '';
  let source = '';

  // 1. Try OpenSSL CLI to parse extensions
  try {
    const text = execSync(`openssl x509 -in "${resolvedPath}" -noout -text 2>/dev/null`, { encoding: 'utf8' });

    // Look for Authority Key Identifier
    let match = text.match(/Authority Key Identifier:[^\n]*\n\s*keyid:([0-9A-Fa-f:]+)/i);
    if (match) {
      hexKeyId = match[1].replace(/[^0-9A-Fa-f]/g, '');
      source = 'Authority Key Identifier (AKI Extension)';
    } else {
      // Look for Subject Key Identifier (common in Root/Issuer CAs)
      match = text.match(/Subject Key Identifier:[^\n]*\n\s*([0-9A-Fa-f:]+)/i);
      if (match) {
        hexKeyId = match[1].replace(/[^0-9A-Fa-f]/g, '');
        source = 'Subject Key Identifier (SKI Extension)';
      }
    }
  } catch (err) { }

  // 2. Fallback: Parse via Node.js crypto X509Certificate and compute SHA-1 of public key (RFC 5280 SPKI SHA-1)
  if (!hexKeyId) {
    try {
      const certBuf = fs.readFileSync(resolvedPath);
      const x509 = new crypto.X509Certificate(certBuf);
      const spkiDer = x509.publicKey.export({ format: 'der', type: 'spki' });

      // Calculate SHA-1 digest according to RFC 5280 method 1
      const sha1 = crypto.createHash('sha1').update(spkiDer).digest();
      hexKeyId = sha1.toString('hex');
      source = 'SHA-1 hash of public key (RFC 5280 SPKI fallback)';
    } catch (err) {
      console.error(`❌ error while parsing the cert: ${err.message}`);
      process.exit(1);
    }
  }

  // Convert hex bytes to Base64URL string
  const base64UrlVal = Buffer.from(hexKeyId, 'hex').toString('base64url');

  if (verbose) {
    console.log('=================================================================');
    console.log('  EUDI WALLET - AKI EXTRACTOR                                    ');
    console.log('=================================================================');
    console.log(`  ✓ Cert File          : ${path.basename(resolvedPath)}`);
    console.log(`  ✓ Path               : ${resolvedPath}`);
    console.log(`  ✓ Source             : ${source}`);
    console.log(`  ✓ Hex Key Identifier : ${hexKeyId.match(/.{1,2}/g).join(':').toUpperCase()}`);
    console.log(`  ✓ Base64URL value    : ${base64UrlVal}\n`);
    console.log('--- DCQL trusted_authorities SNIPPET ---');
    console.log(JSON.stringify({
      "trusted_authorities": [
        {
          "type": "aki",
          "values": [
            base64UrlVal
          ]
        }
      ]
    }, null, 2));
    console.log('\n=================================================================');
  } else {
    // Output ONLY the string value by default as requested
    console.log(base64UrlVal);
  }
}

const { certPath, verbose } = parseArgs();
extractAkiBase64Url(certPath, verbose);
