/**
 * EUDI Wallet WRPAC & WRPRC
 * Binding & Integrity Validator
 * 
 * Verifies the cryptographic and indentity binding between:
 * 1. WRPAC (X.509 or PEM/DER)
 * 2. WRPRC (JWT or X.509)
 * 
 * Usage:
 *   node ./tools/cert-validator.js .certs/access_certificate.pem ./certs/registration_certificate.jwt
 *   node ./tools/cert-validator.js --access ./certs/access_certificate.pem --registration ./certs/registration_certificate.jwt
 *   node ./tools/cert-validator.js -a ./certs/access_certificate.pem -r ./certs/registration_certificate.jwt
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function decodeBase64Url(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

function base64UrlEncode(buffer) {
  return buffer.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function printUsage() {
  console.log(`
=================================================================
  EUDI WALLET - WRPRC/WRPAC BINDING VALIDATOR TOOL
=================================================================

Usage:
  node ./tools/cert-validator.js <ACCESS_CERT_PATH> <REGISTRATION_CERT_PATH>
  
Optional flags:
  node ./tools/cert-validator.js --access ./certs/access_certificate.pem --registration ./certs/registration_certificate.jwt
  node ./tools/cert-validator.js -a ./certs/access_certificate.pem -r ./certs/registration_certificate.jwt
`);
}

function parseArgs() {
  const args = process.argv.slice(2);
  let accessPath = null;
  let regPath = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--access' || arg === '-a') {
      accessPath = args[i + 1];
      i++;
    } else if (arg === '--registration' || arg === '-r') {
      regPath = args[i + 1];
      i++;
    } else if (arg.startsWith('--access=')) {
      accessPath = arg.split('=')[1];
    } else if (arg.startsWith('--registration=')) {
      regPath = arg.split('=')[1];
    } else if (arg === '--help' || arg === '-h') {
      printUsage();
      process.exit(0);
    } else if (!arg.startsWith('-')) {
      if (!accessPath) accessPath = arg;
      else if (!regPath) regPath = arg;
    }
  }

  return { accessPath, regPath };
}

class CertificateBindingValidator {
  constructor() {
    this.report = {
      valid: true,
      errors: [],
      warnings: [],
      info: []
    };
  }

  logError(msg) {
    this.report.valid = false;
    this.report.errors.push(msg);
  }

  logWarning(msg) {
    this.report.warnings.push(msg);
  }

  logInfo(msg) {
    this.report.info.push(msg);
  }

  async validate(accessCertPath, regCertPath) {
    console.log("\n=================================================================");
    console.log("  EUDI WALLET - CERTIFICATE BINDING DIAGNOSTIC REPORT            ");
    console.log("=================================================================\n");

    if (!accessCertPath || !regCertPath) {
      this.logError("Both certificate paths must be provided!");
      printUsage();
      return this.printReport();
    }

    const absAccessPath = path.resolve(process.cwd(), accessCertPath);
    const absRegPath = path.resolve(process.cwd(), regCertPath);

    this.logInfo(`Access Certificate Path: ${absAccessPath}`);
    this.logInfo(`Registration Certificate Path: ${absRegPath}`);

    // 1. Check File Existence
    if (!fs.existsSync(absAccessPath)) {
      this.logError(`Access Certificate not found: ${absAccessPath}`);
      return this.printReport();
    }
    if (!fs.existsSync(absRegPath)) {
      this.logError(`Registration Certificate not found: ${absRegPath}`);
      return this.printReport();
    }

    // 2. Parse Access Certificate (WRPAC)
    console.log("--- 1. ACCESS CERTIFICATE (WRPAC) META DATA & HASHES ---");
    let accessCertRaw = fs.readFileSync(absAccessPath);
    let x509Access = null;

    try {
      x509Access = new crypto.X509Certificate(accessCertRaw);
      this.logInfo(`X.509 Access Certificate parsed successfully`);
      this.logInfo(`Subject: ${x509Access.subject}`);
      this.logInfo(`Issuer:  ${x509Access.issuer}`);
      this.logInfo(`Validity: from ${x509Access.validFrom} to ${x509Access.validTo}`);

      const now = new Date();
      if (now < new Date(x509Access.validFrom) || now > new Date(x509Access.validTo)) {
        this.logWarning(`Access Certificate has expired or is not valid yet`);
      } else {
        this.logInfo(`Status: within validity period`);
      }
    } catch (e) {
      this.logError(`Access Certificate could not be parsed as X.509: ${e.message}`);
      return this.printReport();
    }

    // Access Cert DER & calculate hashes
    const accessDer = x509Access.raw;
    const sha256HashBuf = crypto.createHash('sha256').update(accessDer).digest();
    const base64urlHash = base64UrlEncode(sha256HashBuf);
    const hexHash = sha256HashBuf.toString('hex');
    const expectedClientIdX509Hash = `x509_hash:${base64urlHash}`;

    console.log(`  ✓ DER length: ${accessDer.length} Bytes`);
    console.log(`  ✓ SHA-256 (Base64URL): ${base64urlHash}`);
    console.log(`  ✓ SHA-256 (Hex):       ${hexHash}`);
    console.log(`  ✓ HAIP client_id:      ${expectedClientIdX509Hash}`);

    // Public Key Details
    let accessPublicKeyJwk = null;
    try {
      accessPublicKeyJwk = x509Access.publicKey.export({ format: 'jwk' });
      this.logInfo(`Public Key type: ${x509Access.publicKey.asymmetricKeyType.toUpperCase()} (crv: ${accessPublicKeyJwk.crv || 'n/a'})`);
    } catch (e) {
      this.logWarning(`Public Key JWK export failed: ${e.message}`);
    }

    // 3. Parse Registration Certificate (WRPRC)
    console.log("--- 2. REGISTRATION CERTIFICATE (WRPRC) PARSING ---");
    const regContent = fs.readFileSync(absRegPath, 'utf8').trim();
    let regJwtHeader = null;
    let regJwtPayload = null;

    if (regContent.startsWith('eyJ')) {
      this.logInfo(`Registration Certificate detected as JWT`);
      const parts = regContent.split('.');
      if (parts.length !== 3) {
        this.logError(`Invalid JWT format: expected 3 segments, ${parts.length} segments received`);
        return this.printReport();
      }

      try {
        regJwtHeader = JSON.parse(decodeBase64Url(parts[0]));
        this.logInfo(`JWT Header parsed. Algorithm (alg): ${regJwtHeader.alg || 'n/a'}`);
      } catch (e) {
        this.logError(`Error while decoding JWT header in reg cert: ${e.message}`);
        return this.printReport();
      }

      try {
        regJwtPayload = JSON.parse(decodeBase64Url(parts[1]));
        this.logInfo(`JWT Payload parsed.`);
      } catch (e) {
        this.logError(`Error while decoding the jWT payload of the reg cert: ${e.message}`);
        return this.printReport();
      }
    } else {
      this.logWarning(`Registration Certificate is not valid JWT; attempting X.509 parsing...`);
      try {
        const x509Reg = new crypto.X509Certificate(regContent);
        this.logInfo(`Registration Certificate detected as X.509 erkannt; subject: ${x509Reg.subject}`);
      } catch (e) {
        this.logError(`Registration Certificate could not be parsed`);
        return this.printReport();
      }
    }

    // 4. Validate Binding & Alignment (WRPAC <-> WRPRC)
    console.log("--- 3. BINDING VERIFICATION (WRPAC <-> WRPRC ALIGNMENT) ---");

    if (regJwtPayload) {
      // Check A: client_id / sub / rp_client_id Match
      const payloadClientId = regJwtPayload.client_id || regJwtPayload.sub || regJwtPayload.rp_client_id;

      if (payloadClientId) {
        this.logInfo(`Registration Certificate declared client ID / subject: '${payloadClientId}'`);
        if (payloadClientId === expectedClientIdX509Hash) {
          this.logInfo(`MATCH: client ID '${payloadClientId}' matches with WRPAC client_id`);
        } else if (payloadClientId.includes(base64urlHash)) {
          this.logInfo(`MATCH: hash component of client_id found in reg cert`);
        } else {
          this.logError(`MISMATCH (NOT_BOUND_TO_REQUESTER): reg cert issues to '${payloadClientId}' but WRPAC client_id '${expectedClientIdX509Hash}' found`);
        }
      } else {
        this.logWarning(`Registration Certificate payload does not contain 'client_id', 'sub' or 'rp_client_id'`);
      }

      // Check B: Certificate Hash (cert_hash / x509_cert_hash / x5c_hash / x5t#S256)
      const certHashClaim = regJwtPayload.cert_hash || regJwtPayload.x509_cert_hash || regJwtPayload.x5c_hash || regJwtPayload['x5t#S256'];
      if (certHashClaim) {
        this.logInfo(`Registration Certificate contains cert hash claim: '${certHashClaim}'`);
        if (certHashClaim === base64urlHash || certHashClaim === hexHash) {
          this.logInfo(`MATCH: cert hash in WRPRC matches with WRPAC SHA-256 hash`);
        } else {
          this.logError(`MISMATCH (NOT_BOUND_TO_REQUESTER): WRPRC cert_hash ('${certHashClaim}') deviated from WRPAC SHA-256 hash ('${base64urlHash}')`);
        }
      }

      // Check C: Public Key / JWK Binding Check
      if (regJwtPayload.jwk || regJwtPayload.sub_jwk || regJwtPayload.client_metadata?.jwks) {
        const embeddedJwk = regJwtPayload.jwk || regJwtPayload.sub_jwk || regJwtPayload.client_metadata?.jwks?.keys?.[0];
        if (embeddedJwk && accessPublicKeyJwk) {
          if (embeddedJwk.x === accessPublicKeyJwk.x && embeddedJwk.y === accessPublicKeyJwk.y) {
            this.logInfo(`MATCH: public key (JWK coordinates x/y) in WRPRC matches WRPAC`);
          } else {
            this.logError(`MISMATCH: WRPRC public key (JWK) does not match with WRPAC public key`);
          }
        }
      }

      // Check D: Expiration of Registration Certificate
      const nowSec = Math.floor(Date.now() / 1000);
      if (regJwtPayload.exp) {
        const expDate = new Date(regJwtPayload.exp * 1000);
        if (nowSec > regJwtPayload.exp) {
          this.logError(`Registration Certificate JWT has expired (exp: ${regJwtPayload.exp} -> ${expDate.toISOString()})!`);
        } else {
          this.logInfo(`Registration Certificate JWT not yet valid ${expDate.toISOString()}.`);
        }
      }
    }

    return this.printReport();
  }

  printReport() {
    console.log("=================================================================");
    console.log("                     RESULTS                                     ");
    console.log("=================================================================");

    if (this.report.info.length > 0) {
      console.log("[INFO]:");
      this.report.info.forEach(msg => console.log(`  ✓ ${msg}`));
    }

    if (this.report.warnings.length > 0) {
      console.log("[WARNINGS]:");
      this.report.warnings.forEach(msg => console.log(`  ⚠️  ${msg}`));
    }

    if (this.report.errors.length > 0) {
      console.log("[ERRORS]:");
      this.report.errors.forEach(msg => console.log(`  ❌ ${msg}`));
    }

    console.log("\n-----------------------------------------------------------------");
    if (this.report.valid) {
      console.log("STATUS: ✅ VALID BINDING");
    } else {
      console.log("STATUS: ❌ BINDING ERROR");
    }
    console.log("-----------------------------------------------------------------\n");

    return this.report.valid;
  }
}

async function main() {
  const { accessPath, regPath } = parseArgs();
  const validator = new CertificateBindingValidator();
  const success = await validator.validate(accessPath, regPath);
  process.exit(success ? 0 : 1);
}

main();
