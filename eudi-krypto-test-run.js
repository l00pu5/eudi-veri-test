/**
 * EUDI Wallet Sandbox - Cryptographic E2E Handshake Demo
 * 
 * Dieses Skript demonstriert den mathematisch präzisen Ablauf einer
 * Ende-zu-Ende-Verschlüsselung (JWE) im EUDI-Wallet-Szenario (OpenID4VP).
 * 
 * Es wird ausschließlich das native Node.js 'crypto'-Modul verwendet.
 * Keine externen Abhängigkeiten erforderlich!
 * 
 * Ablauf:
 * 1. Empfänger (Relying Party / Verifier) erzeugt ein statisches P-256 Schlüsselpaar.
 * 2. Sender (Wallet) erzeugt ein temporäres (ephemeres) P-256 Schlüsselpaar.
 * 3. Wallet führt ein ECDH-Key-Agreement durch und leitet einen AES-128-Schlüssel ab (Concat KDF).
 * 4. Wallet verschlüsselt die Ausweisdaten (AES-128-GCM) und erzeugt ein JWE (Kompaktformat).
 * 5. Verifier empfängt das JWE, extrahiert den ephemeren Schlüssel, berechnet denselben AES-Schlüssel
 *    und entschlüsselt die Ausweisdaten im RAM.
 */

const crypto = require('crypto');

// Farben für eine schöne Terminal-Ausgabe
const C_RESET = "\x1b[0m";
const C_BOLD = "\x1b[1m";
const C_GREEN = "\x1b[32m";
const C_CYAN = "\x1b[36m";
const C_YELLOW = "\x1b[33m";
const C_RED = "\x1b[31m";

/**
 * Concat KDF (Kompakt-KDF gemäß RFC 7518 / NIST SP 800-56A)
 * Leitet aus dem gemeinsamen Diffie-Hellman-Geheimnis den symmetrischen Schlüssel ab.
 */
function deriveConcatKDF(sharedSecret, keyLenBytes, alg, apu = null, apv = null) {
    const roundOutputs = [];
    let counter = 1;
    const keyLenBits = keyLenBytes * 8;
    
    // AlgorithmID: 32-Bit Längenpräfix + Algorithmus-String (ASCII)
    const algBuffer = Buffer.from(alg, 'ascii');
    const algLen = Buffer.alloc(4);
    algLen.writeUInt32BE(algBuffer.length, 0);
    const algorithmID = Buffer.concat([algLen, algBuffer]);
    
    // PartyUInfo (apu)
    const apuBuffer = apu ? Buffer.from(apu, 'base64url') : Buffer.alloc(0);
    const apuLen = Buffer.alloc(4);
    apuLen.writeUInt32BE(apuBuffer.length, 0);
    const partyUInfo = Buffer.concat([apuLen, apuBuffer]);
    
    // PartyVInfo (apv)
    const apvBuffer = apv ? Buffer.from(apv, 'base64url') : Buffer.alloc(0);
    const apvLen = Buffer.alloc(4);
    apvLen.writeUInt32BE(apvBuffer.length, 0);
    const partyVInfo = Buffer.concat([apvLen, apvBuffer]);
    
    // SuppPubInfo: Key-Länge in Bits (32-Bit Big-Endian)
    const suppPubInfo = Buffer.alloc(4);
    suppPubInfo.writeUInt32BE(keyLenBits, 0);
    
    // Zusammenbau der "OtherInfo"-Struktur
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

async function runDemo() {
    console.log(`${C_BOLD}${C_CYAN}================================================================${C_RESET}`);
    console.log(`${C_BOLD}${C_CYAN}🔐 EUDI WALLET - MATHEMATISCHER E2E HANDSHAKE-DEMO RUN (Node.js)${C_RESET}`);
    console.log(`${C_BOLD}${C_CYAN}================================================================${C_RESET}\n`);

    // Die zu übertragenden fiktiven Ausweisdaten von Erika Mustermann
    const rawClaims = {
        given_name: "Erika",
        family_name: "Mustermann",
        birthdate: "1998-08-12",
        is_over_18: true,
        address: {
            street_address: "Heidestraße 17",
            locality: "Köln",
            postal_code: "50667",
            country: "DE"
        }
    };

    console.log(`${C_BOLD}[Schritt 1] Empfänger (Relying Party / Verifier) bereitet Schlüssel vor...${C_RESET}`);
    // Der Verifier erzeugt sein Schlüsselpaar (asymmetrisch)
    const rpKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const rpPrivateKey = rpKeyPair.privateKey;
    const rpPublicKeyJwk = rpKeyPair.publicKey.export({ format: 'jwk' });
    console.log(`   ✔ Verifier EC P-256 Public Key erzeugt (kid: "rp-key-1")`);
    console.log(`   ✔ Öffentliche X-Koordinate: ${C_YELLOW}${rpPublicKeyJwk.x}${C_RESET}`);
    console.log(`   ✔ Öffentliche Y-Koordinate: ${C_YELLOW}${rpPublicKeyJwk.y}${C_RESET}\n`);


    console.log(`${C_BOLD}[Schritt 2] Wallet (Sender) initiiert Verschlüsselung für den Kanal...${C_RESET}`);
    // Das Wallet erzeugt einen flüchtigen (ephemeren) Schlüssel für diese eine Transaktion
    const walletEphemeralKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const epkJwk = walletEphemeralKeyPair.publicKey.export({ format: 'jwk' });
    console.log(`   ✔ Ephemerer Wallet-Schlüssel (epk) erzeugt.`);
    console.log(`   ✔ Ephemere X-Koordinate: ${C_YELLOW}${epkJwk.x}${C_RESET}\n`);


    console.log(`${C_BOLD}[Schritt 3] Wallet führt Diffie-Hellman-Berechnung (ECDH) aus...${C_RESET}`);
    // Wallet nimmt seinen privaten Schlüssel und den öffentlichen des Verifiers
    const walletSharedSecret = crypto.diffieHellman({
        privateKey: walletEphemeralKeyPair.privateKey,
        publicKey: crypto.createPublicKey({ key: rpPublicKeyJwk, format: 'jwk' })
    });
    console.log(`   ✔ Gemeinsames Geheimnis (Shared Secret) berechnet: ${C_GREEN}${walletSharedSecret.toString('hex').slice(0, 32)}... (${walletSharedSecret.length} Bytes)${C_RESET}`);

    // Concat KDF anwenden, um den AES-128-GCM Schlüssel abzuleiten
    const walletAesKey = deriveConcatKDF(walletSharedSecret, 16, "A128GCM");
    console.log(`   ✔ Symmetrischer AES-128 Schlüssel via Concat KDF abgeleitet: ${C_GREEN}${walletAesKey.toString('hex')}${C_RESET}\n`);


    console.log(`${C_BOLD}[Schritt 4] Wallet verschlüsselt Ausweisdaten (AES-128-GCM)...${C_RESET}`);
    const jweHeader = {
        alg: "ECDH-ES",
        enc: "A128GCM",
        epk: {
            kty: "EC",
            crv: "P-256",
            x: epkJwk.x,
            y: epkJwk.y
        }
    };
    
    const jweHeaderB64 = Buffer.from(JSON.stringify(jweHeader)).toString('base64url');
    const iv = crypto.randomBytes(12); // GCM verlangt einen 12-Byte Initialisierungsvektor (IV)
    
    const cipher = crypto.createCipheriv('aes-128-gcm', walletAesKey, iv);
    // Der JWE Header geht als Additional Authenticated Data (AAD) in die GCM-Verschlüsselung ein!
    cipher.setAAD(Buffer.from(jweHeaderB64, 'ascii'));
    
    const payloadBuffer = Buffer.from(JSON.stringify(rawClaims), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(payloadBuffer), cipher.final()]);
    const tag = cipher.getAuthTag(); // 16-Byte Authentifizierungstag für Integritätsschutz

    // Kompaktformat zusammensetzen (5 Segmente durch Punkte getrennt):
    // Header . Verschlüsselter_Key(leer bei ECDH-ES) . IV . Ciphertext . Tag
    const jweCompactString = `${jweHeaderB64}..${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${tag.toString('base64url')}`;
    
    console.log(`   ✔ Verschlüsselung abgeschlossen.`);
    console.log(`   ✔ Erzeugter JWE-Token-String (übertragungsbereit):`);
    console.log(`     ${C_YELLOW}${jweCompactString.slice(0, 70)}...[abgekürzt]...${jweCompactString.slice(-30)}${C_RESET}\n`);


    console.log(`${C_BOLD}[Schritt 5] Verifier empfängt JWE und startet Entschlüsselung...${C_RESET}`);
    const jweParts = jweCompactString.split('.');
    if (jweParts.length !== 5) {
        throw new Error("Ungültiges JWE-Kompaktformat.");
    }
    const [recHeaderB64, recEncKeyB64, recIvB64, recCiphertextB64, recTagB64] = jweParts;
    
    // Header dekodieren, um den ephemeren Public Key der Wallet (epk) auszulesen
    const recHeader = JSON.parse(Buffer.from(recHeaderB64, 'base64url').toString('utf8'));
    console.log(`   ✔ Empfangener Header gelesen. Verschlüsselungsverfahren: ${C_GREEN}${recHeader.alg} + ${recHeader.enc}${C_RESET}`);
    
    const walletPublicKey = crypto.createPublicKey({
        key: recHeader.epk,
        format: 'jwk'
    });


    console.log(`${C_BOLD}[Schritt 6] Verifier berechnet mathematisches Gegenstück (ECDH-ES)...${C_RESET}`);
    // Verifier nutzt seinen privaten Schlüssel und den extrahierten ephemeren Wallet-Schlüssel
    const verifierSharedSecret = crypto.diffieHellman({
        privateKey: rpPrivateKey,
        publicKey: walletPublicKey
    });
    console.log(`   ✔ Gemeinsames Geheimnis berechnet: ${C_GREEN}${verifierSharedSecret.toString('hex').slice(0, 32)}...${C_RESET}`);

    // Verifier führt exakt dieselbe Concat KDF-Ableitung durch
    const verifierAesKey = deriveConcatKDF(verifierSharedSecret, 16, "A128GCM");
    console.log(`   ✔ Verifier leitet symmetrischen AES-Schlüssel ab: ${C_GREEN}${verifierAesKey.toString('hex')}${C_RESET}`);
    
    // Prüfen, ob beide Schlüssel identisch sind
    const keysMatch = walletAesKey.equals(verifierAesKey);
    if (keysMatch) {
        console.log(`   ✔ ${C_GREEN}Kryptografischer Abgleich erfolgreich! Beide Schlüssel stimmen überein. (DH-Magie!)${C_RESET}\n`);
    } else {
        console.log(`   ❌ ${C_RED}Kryptografischer Fehler: Schlüssel stimmen nicht überein!${C_RESET}\n`);
        return;
    }


    console.log(`${C_BOLD}[Schritt 7] Verifier entschlüsselt Ciphertext und validiert GCM-Tag...${C_RESET}`);
    try {
        const decipher = crypto.createDecipheriv('aes-128-gcm', verifierAesKey, Buffer.from(recIvB64, 'base64url'));
        decipher.setAAD(Buffer.from(recHeaderB64, 'ascii'));
        decipher.setAuthTag(Buffer.from(recTagB64, 'base64url'));
        
        const decryptedBuffer = Buffer.concat([
            decipher.update(Buffer.from(recCiphertextB64, 'base64url')),
            decipher.final()
        ]);
        
        const decryptedClaims = JSON.parse(decryptedBuffer.toString('utf8'));
        console.log(`   ✔ ${C_GREEN}GCM-Integritätsprüfung erfolgreich bestanden. Daten sind unverändert!${C_RESET}`);
        console.log(`   ✔ ${C_GREEN}Ausweisdaten erfolgreich entschlüsselt:${C_RESET}`);
        console.log(JSON.stringify(decryptedClaims, null, 2));
        
        console.log(`\n${C_BOLD}${C_GREEN}🎉 ERFOLG! Die verschlüsselte E2E-Übertragung war zu 100% korrekt!${C_RESET}`);
    } catch (e) {
        console.error(`   ❌ ${C_RED}Entschlüsselung fehlgeschlagen! Eventuelle Datenmanipulation erkannt: ${e.message}${C_RESET}`);
    }
}

// Start der Krypto-Demonstration
runDemo();
