/**
 * EUDI WALLET - WRPRC & CRL INSPECTOR TOOL
 * 
 * Decodes WRPRC JWTs (Wallet Relying Party Registration Certificate)
 * and checks X.509 CRL Distribution Points / AIA / Trust Rules
 * 
 * Usage: node eudi-wrprc-crl-inspector.js <WRPRC_PATH> [--verbose]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

function base64UrlDecode(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) {
    b64 += '=';
  }
  return Buffer.from(b64, 'base64').toString('utf8');
}

class WrprcInspector {
  constructor(verbose = false) {
    this.verbose = verbose;
    this.report = {
      validForWallet: true,
      issues: [],
      warnings: [],
      certChain: []
    };
  }

  logIssue(msg) {
    this.report.validForWallet = false;
    this.report.issues.push(msg);
  }

  logWarning(msg) {
    this.report.warnings.push(msg);
  }

  inspect(inputStr) {
    console.log("=================================================================");
    console.log("   EUDI WALLET - WRPRC JWT & X.509 CRL INSPECTION TOOL           ");
    console.log("=================================================================\n");

    let jwtStr = inputStr.trim();
    if (fs.existsSync(jwtStr)) {
      console.log(`ℹ️ reading WRPRC JWT from file: ${jwtStr}`);
      jwtStr = fs.readFileSync(jwtStr, 'utf8').trim();
    } else {
      console.log(`ℹ️ reading WRPRC from string...`);
    }

    const parts = jwtStr.split('.');
    if (parts.length !== 3) {
      console.error("❌ error: invalid JWT format (3 segments were expected)");
      return this.printSummary();
    }

    // 1. Header parsing
    let header;
    try {
      header = JSON.parse(base64UrlDecode(parts[0]));
      console.log("✓ JWS Header decoded successfully");
      console.log(`  - Signature Algorithm (alg): ${header.alg || 'n/a'}`);
      console.log(`  - Token Type (typ):          ${header.typ || 'n/a'}`);
    } catch (e) {
      console.error("❌ error while parsing JWS header:", e.message);
      return this.printSummary();
    }

    // 2. Payload parsing (WRPRC Verifier Info)
    try {
      const payload = JSON.parse(base64UrlDecode(parts[1]));
      console.log("\n✓ WRPRC Payload (Registration Details):");
      if (payload.iss) console.log(`  - Issuer (iss)         : ${payload.iss}`);
      if (payload.sub) console.log(`  - Subject / client_id  : ${payload.sub}`);
      if (payload.iat) console.log(`  - Issued at (iat).     : ${new Date(payload.iat * 1000).toISOString()}`);
      if (payload.exp) console.log(`  - Expiration date (exp): ${new Date(payload.exp * 1000).toISOString()}`);

      if (payload.verifier_info) {
        console.log(`  - Verifier Name        : ${payload.verifier_info.name || 'n/a'}`);
        if (payload.verifier_info.allowed_credentials) {
          console.log(`  - Allowed credentials  : ${JSON.stringify(payload.verifier_info.allowed_credentials)}`);
        }
      }
    } catch (e) {
      console.log("⚠️ unable to parse payload as JSON");
    }

    // 3. x5c Chain Check
    if (!header.x5c || !Array.isArray(header.x5c) || header.x5c.length === 0) {
      console.error("❌ JWS header does not contain 'x5c' certificate chain");
      this.logIssue("No 'x5c' header found in JWT");
      return this.printSummary();
    }

    console.log(`✓ 'x5c' certificate chain found (${header.x5c.length} cert(s))`);

    header.x5c.forEach((certB64, idx) => {
      this.inspectCertificate(certB64, idx, header.x5c.length);
    });

    return this.printSummary();
  }

  inspectCertificate(certB64, index, total) {
    const certDer = Buffer.from(certB64, 'base64');
    const role = index === 0 ? "Leaf (Registration Certificate / WRPRC)" : (index === total - 1 ? "Root / Trust Anchor" : "Intermediate CA Signer");

    console.log("-----------------------------------------------------------------");
    console.log(` 📜 CERTIFICATE [${index}]: ${role}`);
    console.log("-----------------------------------------------------------------");

    let x509;
    try {
      x509 = new crypto.X509Certificate(certDer);
      console.log(`  Subject  : ${x509.subject}`);
      console.log(`  Issuer   : ${x509.issuer}`);
      console.log(`  Valid    : From ${x509.validFrom} until ${x509.validTo}`);
      console.log(`  Serial   : ${x509.serialNumber}`);

      const now = new Date();
      if (now < new Date(x509.validFrom) || now > new Date(x509.validTo)) {
        this.logIssue(`Cert [${index}] is outside of its validity period`);
        console.log(`  ❌ certificate currently NOT VALID`);
      } else {
        console.log(`  ✓ certificate is valid`);
      }
    } catch (err) {
      this.logIssue(`Certificate [${index}] could not be parsed`);
      console.log(`  ❌ error while parsing: ${err.message}`);
      return;
    }

    // OpenSSL Detailed Analysis
    try {
      const opensslText = execSync('openssl x509 -inform DER -text -noout', { input: certDer, encoding: 'utf8' });

      console.log("  --- X.509 CRL & EXT (Revocation & Extensions) ---");

      // A. CRL Distribution Points Check
      if (opensslText.includes("X509v3 CRL Distribution Points")) {
        console.log("  ✅ 'X509v3 CRL Distribution Points' found");
        const lines = opensslText.split('\n');
        let capturing = false;
        lines.forEach(l => {
          if (l.includes("X509v3 CRL Distribution Points:")) capturing = true;
          else if (capturing && l.trim().startsWith("X509v3")) capturing = false;
          else if (capturing && l.trim()) console.log(`     ${l.trim()}`);
        });
      } else {
        console.log("  ❌ NO 'X509v3 CRL Distribution Points' EXT FOUND");
        this.logIssue(`Certificate [${index}] ('${x509.subject}') does not have HTTP CRL Distribution Point`);
      }

      // B. AIA / OCSP Check
      if (opensslText.includes("Authority Information Access")) {
        console.log("\n  ℹ️  Authority Information Access (AIA / OCSP Endpoints):");
        const lines = opensslText.split('\n');
        let capturing = false;
        lines.forEach(l => {
          if (l.includes("Authority Information Access:")) capturing = true;
          else if (capturing && l.trim().startsWith("X509v3")) capturing = false;
          else if (capturing && l.trim()) console.log(`     ${l.trim()}`);
        });
      } else {
        console.log("  ℹ️  no Authority Information Access (AIA) available");
      }

      // C. Key Usage
      if (opensslText.includes("X509v3 Key Usage")) {
        const lines = opensslText.split('\n');
        let capturing = false;
        lines.forEach(l => {
          if (l.includes("X509v3 Key Usage:")) capturing = true;
          else if (capturing && l.trim().startsWith("X509v3")) capturing = false;
          else if (capturing && l.trim()) console.log(`  ✓ Key Usage: ${l.trim()}`);
        });
      }

      if (this.verbose) {
        console.log("  --- OPENSSL TEXT-DUMP ---");
        console.log(opensslText);
      }

    } catch (err) {
      console.log(`  ⚠️ OpenSSL execution has failed: ${err.message}`);
    }

    console.log();
  }

  printSummary() {
    console.log("=================================================================");
    console.log("                     RESULTS                                     ");
    console.log("=================================================================");

    if (this.report.issues.length > 0) {
      console.log("[ERRORS]:");
      this.report.issues.forEach(iss => console.log(`  ❌ ${iss}`));
    }

    if (this.report.warnings.length > 0) {
      console.log("[WARNINGS]:");
      this.report.warnings.forEach(w => console.log(`  ⚠️  ${w}`));
    }

    console.log("-----------------------------------------------------------------");
    if (this.report.validForWallet) {
      console.log("STATUS: ✅ VALID");
    } else {
      console.log("STATUS: ❌ INVALID");
    }
    console.log("-----------------------------------------------------------------\n");
    return this.report;
  }
}

// CLI Execution Wrapper
if (require.main === module) {
  const args = process.argv.slice(2);
  const verbose = args.includes('--verbose');
  const cleanArgs = args.filter(a => a !== '--verbose');

  if (cleanArgs.length === 0) {
    console.log("Usage    : node eudi-wrprc-crl-inspector.js <WRPRC_JWT_OR_FILE> [--verbose]");
    console.log("Example  : node eudi-wrprc-crl-inspector.js certs/registration_certificate.jwt");
    process.exit(1);
  } else {
    const inspector = new WrprcInspector(verbose);
    inspector.inspect(cleanArgs[0]);
  }
}

module.exports = WrprcInspector;
