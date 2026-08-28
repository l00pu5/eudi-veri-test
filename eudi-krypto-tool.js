const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Colors for terminal output
const C_RESET = "\x1b[0m";
const C_BOLD = "\x1b[1m";
const C_GREEN = "\x1b[32m";
const C_BLUE = "\x1b[34m";
const C_YELLOW = "\x1b[33m";
const C_RED = "\x1b[31m";

function showHelp() {
    console.log(`
${C_BOLD}${C_BLUE}EUDI Wallet Cryptographic CLI Utility (Native Node.js)${C_RESET}
Usage:
  node eudi-krypto-tool.js <command> [options]

Commands:
  ${C_BOLD}gencert${C_RESET}       Generiert ein privates EC-Schlüsselpaar und ein selbstsigniertes
                X.509-Zertifikat mit SAN (Subject Alternative Name) für client.example.org.
                Optionen:
                  --out-key=<path>  Standard: ./rp-private-key.pem
                  --out-cert=<path> Standard: ./rp-cert.pem

  ${C_BOLD}sign${C_RESET}          Erzeugt ein signiertes JWS-Dokument (z.B. JAR Request Object).
                Fügt das Zertifikat automatisch als x5c-Kette in den Header ein.
                Optionen:
                  --key=<path>      Pfad zum privaten EC-Schlüssel (PEM)
                  --cert=<path>     Pfad zum X.509-Zertifikat (PEM) für x5c-Header
                  --payload=<json>  Roher JSON-String oder Pfad zu einer JSON-Datei
                  --out=<path>      Ausgabepfad für das signierte JWS (Standard: stdout)

  ${C_BOLD}encrypt${C_RESET}       Verschlüsselt ein Payload im JWE-Format (ECDH-ES + A128GCM).
                Optionen:
                  --pubkey=<path>   Pfad zum öffentlichen EC-Schlüssel des Empfängers (PEM/JWK-Datei)
                  --payload=<str>   Text-Payload oder Pfad zu einer Datei
                  --out=<path>      Ausgabepfad für das JWE-Token (Standard: stdout)

  ${C_BOLD}decrypt${C_RESET}       Entschlüsselt ein JWE-Kompakt-Token.
                Optionen:
                  --key=<path>      Pfad zum privaten EC-Schlüssel des Empfängers (PEM)
                  --jwe=<string>    Das JWE-Kompakt-Token (oder Pfad zu einer Datei)

Beispiele:
  # 1. Schlüssel und Zertifikat generieren
  node eudi-krypto-tool.js gencert

  # 2. JAR Request Object (JWS) signieren
  node eudi-krypto-tool.js sign --key=rp-private-key.pem --cert=rp-cert.pem --payload='{"nonce":"123","client_id":"x509_san_dns:client.example.org"}'
    `);
}

// Helper: Parse CLI arguments
function parseArgs() {
    const args = process.argv.slice(3);
    const options = {};
    args.forEach(arg => {
        if (arg.startsWith('--')) {
            const parts = arg.slice(2).split('=');
            const key = parts[0];
            const val = parts.slice(1).join('=');
            options[key] = val;
        }
    });
    return options;
}

// Helper: Read payload (supports raw string or file path)
function getPayload(input) {
    if (!input) return null;
    try {
        if (fs.existsSync(input)) {
            return fs.readFileSync(input, 'utf8');
        }
    } catch (e) {}
    return input;
}

// COMMAND: gencert
function handleGenCert(options) {
    const keyPath = options['out-key'] || './rp-private-key.pem';
    const certPath = options['out-cert'] || './rp-cert.pem';

    console.log(`${C_BLUE}[gencert] Generiere Zertifikatskette für client.example.org...${C_RESET}`);
    try {
        const { execSync } = require('child_process');
        const cnfContent = `[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = client.example.org

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:client.example.org`;

        const cnfPath = path.join(path.dirname(keyPath), 'openssl-temp.cnf');
        fs.writeFileSync(cnfPath, cnfContent);

        execSync(`openssl ecparam -name prime256v1 -genkey -noout -out ${keyPath}`);
        execSync(`openssl req -new -x509 -key ${keyPath} -out ${certPath} -days 365 -config ${cnfPath}`);
        
        fs.unlinkSync(cnfPath);

        console.log(`${C_GREEN}✔ Schlüssel erfolgreich generiert:${C_RESET}`);
        console.log(`  Private Key: ${C_BOLD}${keyPath}${C_RESET}`);
        console.log(`  Zertifikat:  ${C_BOLD}${certPath}${C_RESET}`);
    } catch (err) {
        console.error(`${C_RED}❌ Fehler bei der Zertifikatsgenerierung mit OpenSSL. Weiche auf reinen JS-Key-Keygen aus...${C_RESET}`);
        // Fallback: Generate keys only (no self-signed cert since native Node can't easily write X.509 certs from scratch without forge)
        const { generateKeyPairSync } = crypto;
        const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        fs.writeFileSync(keyPath, privateKey.export({ type: 'sec1', format: 'pem' }));
        fs.writeFileSync(certPath, publicKey.export({ type: 'spki', format: 'pem' }));
        console.log(`${C_YELLOW}⚠ Nur Schlüsselpaar generiert (kein X.509-Zertifikat vorhanden, da openssl fehlschlug).${C_RESET}`);
    }
}

// COMMAND: sign (JWS with x5c)
function handleSign(options) {
    const keyPath = options['key'];
    const certPath = options['cert'];
    const payloadInput = options['payload'];
    const outPath = options['out'];

    if (!keyPath || !payloadInput) {
        console.error(`${C_RED}❌ Fehler: --key und --payload sind zwingend erforderlich.${C_RESET}`);
        process.exit(1);
    }

    const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
    const privateKey = crypto.createPrivateKey(privateKeyPem);

    let certBase64 = null;
    if (certPath) {
        const certPem = fs.readFileSync(certPath, 'utf8');
        certBase64 = certPem
            .replace(/-----\s*(BEGIN|END)\s+CERTIFICATE\s*-----/g, '')
            .replace(/[\r\n]/g, '');
    }

    const payloadStr = getPayload(payloadInput);
    let payloadObj;
    try {
        payloadObj = JSON.parse(payloadStr);
    } catch (err) {
        console.error(`${C_RED}❌ Fehler: Payload ist kein gültiges JSON.${C_RESET}`);
        process.exit(1);
    }

    // Sign JWS
    const header = {
        alg: 'ES256',
        typ: 'oauth-authz-req+jwt'
    };
    if (certBase64) {
        header.x5c = [ certBase64 ];
    }

    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');

    const signatureInput = `${headerB64}.${payloadB64}`;
    const signer = crypto.createSign('SHA256');
    signer.update(signatureInput);
    const signatureB64 = signer.sign(privateKey, 'base64url');

    const jwsCompact = `${signatureInput}.${signatureB64}`;

    if (outPath) {
        fs.writeFileSync(outPath, jwsCompact);
        console.log(`${C_GREEN}✔ JWS erfolgreich signiert und nach ${outPath} exportiert.${C_RESET}`);
    } else {
        console.log(`\n${C_BOLD}${C_GREEN}--- SIGNIERTES JWS-TOKEN (COMPACT) ---${C_RESET}`);
        console.log(jwsCompact);
    }
}

// Concat KDF implementation matching HAIP/RFC 7518
function deriveConcatKDF(sharedSecret, keyLenBytes, alg, apu, apv) {
    const roundOutputs = [];
    let counter = 1;
    const keyLenBits = keyLenBytes * 8;
    
    const algBuffer = Buffer.from(alg, 'ascii');
    const algLen = Buffer.alloc(4);
    algLen.writeUInt32BE(algBuffer.length, 0);
    const algorithmID = Buffer.concat([algLen, algBuffer]);
    
    const apuBuffer = apu ? Buffer.from(apu, 'base64url') : Buffer.alloc(0);
    const apuLen = Buffer.alloc(4);
    apuLen.writeUInt32BE(apuBuffer.length, 0);
    const partyUInfo = Buffer.concat([apuLen, apuBuffer]);
    
    const apvBuffer = apv ? Buffer.from(apv, 'base64url') : Buffer.alloc(0);
    const apvLen = Buffer.alloc(4);
    apvLen.writeUInt32BE(apvBuffer.length, 0);
    const partyVInfo = Buffer.concat([apvLen, apvBuffer]);
    
    const suppPubInfo = Buffer.alloc(4);
    suppPubInfo.writeUInt32BE(keyLenBits, 0);
    
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

// COMMAND: encrypt (JWE)
function handleEncrypt(options) {
    const pubKeyPath = options['pubkey'];
    const payloadInput = options['payload'];
    const outPath = options['out'];

    if (!pubKeyPath || !payloadInput) {
        console.error(`${C_RED}❌ Fehler: --pubkey und --payload sind erforderlich.${C_RESET}`);
        process.exit(1);
    }

    const payload = getPayload(payloadInput);
    const rawPubKey = fs.readFileSync(pubKeyPath, 'utf8');

    let recipientPubKey;
    try {
        if (rawPubKey.trim().startsWith('{')) {
            recipientPubKey = crypto.createPublicKey({ key: JSON.parse(rawPubKey), format: 'jwk' });
        } else {
            recipientPubKey = crypto.createPublicKey(rawPubKey);
        }
    } catch (e) {
        console.error(`${C_RED}❌ Fehler beim Einlesen des Empfänger-Public-Keys:${C_RESET}`, e.message);
        process.exit(1);
    }

    // 1. Ephemeres Schlüsselpaar generieren (für den Absender)
    const ephemeral = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const epkCnf = ephemeral.publicKey.export({ format: 'jwk' });

    // 2. Shared Secret berechnen via ECDH
    const sharedSecret = crypto.diffieHellman({
        privateKey: ephemeral.privateKey,
        publicKey: recipientPubKey
    });

    // 3. Concat KDF zur Erzeugung des AES-128 Schlüssels (16 Bytes)
    const derivedKey = deriveConcatKDF(sharedSecret, 16, 'A128GCM', null, null);

    // 4. Symmetrische AES-GCM Verschlüsselung
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('A128GCM', derivedKey, iv);
    
    const jweHeader = {
        alg: 'ECDH-ES',
        enc: 'A128GCM',
        epk: {
            kty: 'EC',
            crv: 'P-256',
            x: epkCnf.x,
            y: epkCnf.y
        }
    };

    const protectedHeaderB64 = Buffer.from(JSON.stringify(jweHeader)).toString('base64url');
    cipher.setAAD(Buffer.from(protectedHeaderB64, 'ascii'));

    const ciphertext = Buffer.concat([
        cipher.update(Buffer.from(payload, 'utf8')),
        cipher.final()
    ]);
    const tag = cipher.getAuthTag();

    const jweCompact = `${protectedHeaderB64}..${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${tag.toString('base64url')}`;

    if (outPath) {
        fs.writeFileSync(outPath, jweCompact);
        console.log(`${C_GREEN}✔ JWE-Verschlüsselung erfolgreich durchgeführt und nach ${outPath} exportiert.${C_RESET}`);
    } else {
        console.log(`\n${C_BOLD}${C_GREEN}--- VERSCHLÜSSELTES JWE-TOKEN (ECDH-ES + AES-128-GCM) ---${C_RESET}`);
        console.log(jweCompact);
    }
}

// COMMAND: decrypt (JWE)
function handleDecrypt(options) {
    const keyPath = options['key'];
    const jweInput = options['jwe'];

    if (!keyPath || !jweInput) {
        console.error(`${C_RED}❌ Fehler: --key und --jwe sind erforderlich.${C_RESET}`);
        process.exit(1);
    }

    const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
    const privateKey = crypto.createPrivateKey(privateKeyPem);

    const jweString = getPayload(jweInput).trim();
    const parts = jweString.split('.');
    if (parts.length !== 5) {
        console.error(`${C_RED}❌ Fehler: Ungültiges JWE-Kompaktformat. Erwartet werden 5 Segmente.${C_RESET}`);
        process.exit(1);
    }

    const [protectedHeaderB64, encryptedKeyB64, ivB64, ciphertextB64, tagB64] = parts;
    const header = JSON.parse(Buffer.from(protectedHeaderB64, 'base64url').toString('utf8'));

    if (header.alg !== 'ECDH-ES') {
        console.error(`${C_RED}❌ Fehler: Nicht unterstützter JWE-Algorithmus: ${header.alg}.${C_RESET}`);
        process.exit(1);
    }
    if (header.enc !== 'A128GCM') {
        console.error(`${C_RED}❌ Fehler: Nicht unterstützter symmetrischer Algorithmus: ${header.enc}.${C_RESET}`);
        process.exit(1);
    }

    const walletEphemeralPublicKey = crypto.createPublicKey({
        key: header.epk,
        format: 'jwk'
    });

    // 1. Shared Secret berechnen via ECDH (Gegenstelle)
    const sharedSecret = crypto.diffieHellman({
        privateKey: privateKey,
        publicKey: walletEphemeralPublicKey
    });

    // 2. Concat KDF
    const derivedKey = deriveConcatKDF(sharedSecret, 16, 'A128GCM', null, null);

    // 3. Symmetrische Entschlüsselung
    const iv = Buffer.from(ivB64, 'base64url');
    const ciphertext = Buffer.from(ciphertextB64, 'base64url');
    const tag = Buffer.from(tagB64, 'base64url');

    const decipher = crypto.createDecipheriv('A128GCM', derivedKey, iv);
    decipher.setAuthTag(tag);
    decipher.setAAD(Buffer.from(protectedHeaderB64, 'ascii'));

    try {
        const decrypted = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]).toString('utf8');

        console.log(`\n${C_BOLD}${C_GREEN}--- ENTSCHLÜSSELTE PAYLOAD-DATEN ---${C_RESET}`);
        try {
            // Pretty-print JSON if possible
            console.log(JSON.stringify(JSON.parse(decrypted), null, 2));
        } catch (e) {
            console.log(decrypted);
        }
    } catch (err) {
        console.error(`${C_RED}❌ Fehler beim Entschlüsseln oder Integritätsprüfung fehlgeschlagen (Tag Mismatch).${C_RESET}`);
        process.exit(1);
    }
}

// CLI Dispatcher
const command = process.argv[2];
const options = parseArgs();

switch (command) {
    case 'gencert':
        handleGenCert(options);
        break;
    case 'sign':
        handleSign(options);
        break;
    case 'encrypt':
        handleEncrypt(options);
        break;
    case 'decrypt':
        handleDecrypt(options);
        break;
    default:
        showHelp();
        break;
}
