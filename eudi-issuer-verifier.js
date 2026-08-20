/**
 * EUDI Wallet - PID Provider / Credential Issuer Verifier & Issuer Helper
 * 
 * Dieses Modul implementiert die serverseitige Verifizierungs- und Ausstellungslogik
 * für einen EUDI-PID-Provider (Credential Issuer) gemäß den Spezifikationen von
 * OpenID for Verifiable Credential Issuance (OpenID4VCI) 1.0, OpenID HAIP 1.0
 * und dem deutschen Nationalen Architekturkonzept.
 * 
 * Das Modul ist herstellerneutral und verwendet ausschließlich das native Node.js-Modul 'crypto'.
 * 
 * @module EUDIPIDIssuerVerifier
 */

const crypto = require('crypto');

class EUDIPIDIssuerVerifier {
    /**
     * Erstellt eine neue Instanz des Issuers/Verifiziers.
     * @param {Object} config - Konfigurationsparameter des Issuers
     * @param {string} config.issuerId - Eindeutige ID des Credential Issuers (z. B. https://pid-provider.de)
     * @param {string} config.issuerPrivateKeyPem - Privater Signaturschlüssel des Issuers (PEM)
     * @param {string} config.issuerPublicKeyPem - Öffentlicher Signaturschlüssel des Issuers (PEM)
     * @param {Array<string>} config.trustedWalletKeys - Vertrauenswürdige Schlüssel des Wallet-Backends (zur WIA-Verifikation)
     */
    constructor(config) {
        if (!config.issuerId || !config.issuerPrivateKeyPem || !config.issuerPublicKeyPem) {
            throw new Error('Konfigurationsfehler: issuerId, issuerPrivateKeyPem und issuerPublicKeyPem sind erforderlich.');
        }
        this.issuerId = config.issuerId;
        this.issuerPrivateKeyPem = config.issuerPrivateKeyPem;
        this.issuerPublicKeyPem = config.issuerPublicKeyPem;
        this.trustedWalletKeys = config.trustedWalletKeys || [];
        
        // In-Memory-Speicher für aktive Sitzungen und Nonces (im Echtbetrieb Redis/DB)
        this.sessions = new Map();
        this.activeNonces = new Map(); // nonce -> exp
    }

    // =============================================================================
    // KERN-SCHNITTSTELLE 1: UNTERSTÜTZUNG DES TOKEN-ENDPOINTS (DPoP & WIA VALIDIERUNG)
    // =============================================================================

    /**
     * Validiert einen eingehenden Token-Request (Säule 4: Wallet-Echtheit & DPoP-Schlüsselbindung).
     * 
     * @param {Object} params - Parameter des Requests
     * @param {string} params.code - Der erhaltene Authorization Code oder Refresh Token
     * @param {string} params.codeVerifier - PKCE Code Verifier (falls Auth Code Flow)
     * @param {string} params.expectedCodeChallenge - Zuvor im PAR-Schritt gespeicherte PKCE Code Challenge
     * @param {string} params.dpopProof - Das DPoP Proof Token (JWT) des Clients
     * @param {string} params.wiaToken - Das Wallet Instance Attestation (WIA) JWT vom Wallet-Backend
     * @param {string} params.wiaPop - Das WIA Proof of Possession (PoP) JWT
     * @param {string} params.expectedWiaChallenge - Die zuvor für dieses Wallet generierte Challenge
     * @returns {Object} Validierungsergebnis mit DPoP-Schlüsselbindung (Public Key)
     */
    verifyTokenRequest(params) {
        const { code, codeVerifier, expectedCodeChallenge, dpopProof, wiaToken, wiaPop, expectedWiaChallenge } = params;
        const errors = [];

        // 1. PKCE Validierung (falls codeVerifier übergeben wurde)
        if (codeVerifier && expectedCodeChallenge) {
            const calculatedChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
            if (calculatedChallenge !== expectedCodeChallenge) {
                errors.push('PKCE-Verifikation fehlgeschlagen: Code Verifier stimmt nicht mit Challenge überein.');
            }
        }

        // 2. DPoP-Verifikation (Erstabruf des Access Tokens)
        let dpopPublicKeyJwk = null;
        if (dpopProof) {
            try {
                dpopPublicKeyJwk = this._verifyDPoPProof(dpopProof, {
                    expectedHtm: 'POST',
                    expectedHtu: `${this.issuerId}/token`
                });
            } catch (err) {
                errors.push(`DPoP-Validierung fehlgeschlagen: ${err.message}`);
            }
        } else {
            errors.push('DPoP-Proof fehlt im Token-Request. Sender-Constrainting ist zwingend erforderlich.');
        }

        // 3. Wallet Instance Attestation (WIA) Verifikation (Säule 4)
        if (wiaToken && wiaPop) {
            try {
                this._verifyWiaAndPop(wiaToken, wiaPop, expectedWiaChallenge);
            } catch (err) {
                errors.push(`Wallet-Attestierung (WIA) fehlgeschlagen: ${err.message}`);
            }
        } else {
            errors.push('Wallet Instance Attestation (WIA) oder WIA-PoP fehlt im Token-Request.');
        }

        return {
            success: errors.length === 0,
            errors,
            dpopKey: dpopPublicKeyJwk // Dieser Schlüssel schränkt den Access-Token per DPoP ein
        };
    }

    // =============================================================================
    // KERN-SCHNITTSTELLE 2: NONCE-GENERIERUNG (c_nonce & dpop_nonce)
    // =============================================================================

    /**
     * Generiert ein frisches Nonce-Paar zur Absicherung nachfolgender Schlüsselnachweise.
     * 
     * @param {number} [lifespanSeconds=300] - Gültigkeitsdauer der Nonces (Standard: 5 Min)
     * @returns {Object} Nonce-Response-Objekt (c_nonce & dpop_nonce)
     */
    generateNonceResponse(lifespanSeconds = 300) {
        const cNonce = 'c_nonce_' + crypto.randomBytes(16).toString('hex');
        const dpopNonce = 'dpop_nonce_' + crypto.randomBytes(16).toString('hex');
        const exp = Date.now() + (lifespanSeconds * 1000);

        this.activeNonces.set(cNonce, exp);
        this.activeNonces.set(dpopNonce, exp);

        return {
            c_nonce: cNonce,
            c_nonce_expires_in: lifespanSeconds,
            dpop_nonce: dpopNonce
        };
    }

    /**
     * Prüft, ob eine übermittelte Nonce aktiv und gültig ist.
     * Consumed die Nonce direkt (Single-Use-Charakter für High Assurance).
     */
    _validateAndConsumeNonce(nonce) {
        if (!nonce) return false;
        const exp = this.activeNonces.get(nonce);
        if (!exp) return false;
        
        // Löschen für Single-Use (Replay-Schutz)
        this.activeNonces.delete(nonce);

        if (Date.now() > exp) {
            return false; // Abgelaufen
        }
        return true;
    }

    // =============================================================================
    // KERN-SCHNITTSTELLE 3: CREDENTIAL-ENDPOINT (BELEGAUT HENTIZITÄT & SENDER-CONSTRAINT)
    // =============================================================================

    /**
     * Verifiziert einen eingehenden Credential Request.
     * Prüft DPoP (Access Token Bindung) sowie den kryptografischen Schlüsselbesitznachweis (Proof of Possession).
     * 
     * @param {Object} params - Validierungskontext
     * @param {Object} params.credentialRequest - Der JSON-Body des Credential-Requests
     * @param {string} params.dpopProof - Das DPoP Proof Token aus dem HTTP-Header
     * @param {Object} params.accessTokenPayload - Das decodierte Access Token (mit cnf.jwk-Kopplung)
     * @returns {Object} Validierungsergebnis mit dem verifizierten Device-Binding-Schlüssel des Nutzers
     */
    verifyCredentialRequest(params) {
        const { credentialRequest, dpopProof, accessTokenPayload } = params;
        const errors = [];

        // 1. DPoP Verifikation am Credential Endpoint (Sender-Constrainting-Prüfung)
        let dpopPublicKeyJwk = null;
        if (dpopProof) {
            try {
                dpopPublicKeyJwk = this._verifyDPoPProof(dpopProof, {
                    expectedHtm: 'POST',
                    expectedHtu: `${this.issuerId}/credential`
                });

                // Prüfen, ob der DPoP-Schlüssel exakt dem Schlüssel entspricht, an den der Access Token gebunden wurde
                const expectedTokenJwk = accessTokenPayload.cnf?.jwk;
                if (!expectedTokenJwk || JSON.stringify(dpopPublicKeyJwk) !== JSON.stringify(expectedTokenJwk)) {
                    errors.push('DPoP-Schlüsselkonflikt: Der DPoP-Schlüssel entspricht nicht dem registrierten Token-Schlüssel (Sender-Constraint verletzt).');
                }
            } catch (err) {
                errors.push(`DPoP-Validierung fehlgeschlagen: ${err.message}`);
            }
        } else {
            errors.push('DPoP-Proof fehlt im Credential-Request.');
        }

        // 2. Formatprüfung des Requests
        if (!credentialRequest || (!credentialRequest.credential_configuration_id && !credentialRequest.credential_identifier)) {
            errors.push('Ungültiger Credential-Request: Es muss eine credential_configuration_id oder ein credential_identifier übergeben werden.');
            return { success: false, errors };
        }

        // 3. Proof of Possession (PoP) des Device-Binding-Schlüssels validieren
        let devicePublicKeyJwk = null;
        const proofs = credentialRequest.proofs || credentialRequest.proof; // Unterstützt 'proofs' (Array) und Legacy 'proof' (Objekt)
        
        if (proofs && proofs.jwt) {
            const jwtProofArray = Array.isArray(proofs.jwt) ? proofs.jwt : [proofs.jwt];
            const jwtProof = jwtProofArray[0]; // Standardmäßig ein Nachweis

            try {
                devicePublicKeyJwk = this._verifyProofOfPossession(jwtProof);
            } catch (err) {
                errors.push(`Kryptografischer Schlüsselbesitznachweis (PoP) fehlgeschlagen: ${err.message}`);
            }
        } else {
            errors.push('Kryptografischer Schlüsselbesitznachweis (proofs.jwt) fehlt im Credential-Request.');
        }

        return {
            success: errors.length === 0,
            errors,
            devicePublicKeyJwk // Dieser Schlüssel wird kryptografisch in den PID-Ausweis eingebettet (cnf-Claim)
        };
    }

    // =============================================================================
    // KERN-SCHNITTSTELLE 4: PID SIGNATUR- & AUSSTELLUNGSMASCHINE (SD-JWT VC)
    // =============================================================================

    /**
     * Erstellt ein signiertes SD-JWT VC für die übergebenen Claims und bindet es an den Device-Schlüssel des Nutzers.
     * 
     * @param {Object} params - Ausstellungsparameter
     * @param {Object} params.claims - Klartext-Claims (z. B. Erika Mustermanns Daten)
     * @param {Object} params.holderJwk - Der verifizierte öffentliche Device-Binding-Schlüssel der Wallet (cnf.jwk)
     * @param {number} [validityDays=90] - Gültigkeitsdauer des Credentials in Tagen
     * @returns {string} Kompakt-serialisiertes SD-JWT VC (Aussteller-signiertes JWT)
     */
    issuePID(params) {
        const { claims, holderJwk, validityDays = 90 } = params;

        if (!holderJwk) {
            throw new Error('Ausstellungsfehler: Es muss ein holderJwk zur kryptografischen Gerätebindung übergeben werden.');
        }

        // 1. Definition von Salts und Generierung von Hashes für jedes Attribut (Selective Disclosure)
        const disclosures = [];
        const sdHashes = [];

        // Hilfsfunktion zum Erzeugen von JCP-konformen Disclosures: Base64Url([Salt, ClaimName, ClaimValue])
        const addDisclosure = (claimName, claimValue) => {
            const salt = crypto.randomBytes(16).toString('base64url'); // Starker Salt (mindestens 128 Bit Entropie)
            const disclosureArray = [salt, claimName, claimValue];
            const disclosureJson = JSON.stringify(disclosureArray);
            const disclosureBase64 = Buffer.from(disclosureJson).toString('base64url');
            
            disclosures.push(disclosureBase64);

            // Hash berechnen
            const hash = crypto.createHash('sha256').update(disclosureBase64).digest('base64url');
            sdHashes.push(hash);
        };

        // Rekursives/flaches Salting aller übertragenen Claims
        for (const [key, value] of Object.entries(claims)) {
            addDisclosure(key, value);
        }

        // Sortieren der Hashes (Vermeidung von Metadaten-Lecks über die Sortierreihenfolge)
        sdHashes.sort();

        // 2. Erstellung des Haupt-JWT Payloads (Issuer-Signed Part)
        const now = Math.floor(Date.now() / 1000);
        const exp = now + (validityDays * 24 * 60 * 60);

        const jwtPayload = {
            iss: this.issuerId,
            iat: now,
            nbf: now,
            exp: exp,
            vct: 'https://credentials.example.com/identity_credential', // EUDI PID Typ-Metadaten URL
            _sd_alg: 'sha-256',
            _sd: sdHashes,
            cnf: {
                jwk: holderJwk // KRYPTOGRAFISCHE GERÄTEBINDUNG an die Wallet
            }
        };

        // 3. JWS-Signatur erstellen (unter Verwendung des privaten Issuer-Schlüssels)
        const jwtHeader = {
            alg: 'ES256',
            typ: 'dc+sd-jwt', // Typisierung nach HAIP-Profil
            x5c: [ Buffer.from(this.issuerPublicKeyPem).toString('base64') ] // Optionaler Cert-Chain Anhang
        };

        const jwtInput = `${Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')}`;
        
        const signer = crypto.createSign('SHA256');
        signer.update(jwtInput);
        const jwtSignature = signer.sign(this.issuerPrivateKeyPem, 'base64url');

        const issuerSignedJwt = `${jwtInput}.${jwtSignature}`;

        // 4. Zusammensetzen des finalen SD-JWT-Präsentations-Templates
        // Für den Ausstellungs-Endpoint (Credential Response) wird das Issuer-Signed JWT 
        // zusammen mit den Disclosures zurückgeliefert, getrennt durch Tilden (~).
        // Das Key Binding JWT existiert hier noch nicht, dieses wird erst bei der Präsentation angehängt!
        let responseCredentialString = issuerSignedJwt;
        for (const disclosure of disclosures) {
            responseCredentialString += `~${disclosure}`;
        }
        responseCredentialString += '~'; // Schließende Tilde gemäß Standard (ohne KB-JWT)

        return responseCredentialString;
    }

    // =============================================================================
    // INTERNE HILFSMETHODEN FÜR VALIDIERUNG & KRYPTOGRAFIE
    // =============================================================================

    /**
     * Interner Validierungshelfer für DPoP Proof JWTs.
     */
    _verifyDPoPProof(jwtString, constraints) {
        const parts = jwtString.split('.');
        if (parts.length !== 3) {
            throw new Error('Ungültiges DPoP-JWT Format.');
        }

        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        const signature = Buffer.from(parts[2], 'base64url');

        // 1. Header-Prüfung
        if (header.typ !== 'dpop+jwt') {
            throw new Error(`Ungültiger DPoP-Typ: ${header.typ}`);
        }
        if (!header.jwk) {
            throw new Error('DPoP-Header enthält keinen eingebetteten öffentlichen jwk.');
        }

        // 2. Payload-Prüfung (HTM, HTU und Nonce-Freshness)
        if (payload.htm !== constraints.expectedHtm) {
            throw new Error(`DPoP HTM-Fehler. Erwartet: ${constraints.expectedHtm}, erhalten: ${payload.htm}`);
        }
        if (payload.htu !== constraints.expectedHtu) {
            throw new Error(`DPoP HTU-Fehler. Erwartet: ${constraints.expectedHtu}, erhalten: ${payload.htu}`);
        }
        if (payload.nonce) {
            const isNonceValid = this._validateAndConsumeNonce(payload.nonce);
            if (!isNonceValid) {
                throw new Error('DPoP-Nonce ist abgelaufen oder ungültig (Replay-Gefahr).');
            }
        }

        // 3. Kryptografische Verifikation gegen den eingebetteten JWK des Wallets
        const publicKey = crypto.createPublicKey({
            key: header.jwk,
            format: 'jwk'
        });

        const dataToVerify = `${parts[0]}.${parts[1]}`;
        const verify = crypto.createVerify('SHA256');
        verify.update(dataToVerify);

        if (!verify.verify(publicKey, signature)) {
            throw new Error('Die kryptografische DPoP-Signatur ist ungültig.');
        }

        return header.jwk;
    }

    /**
     * Interner Validierungshelfer für Key Proof of Possession JWTs (aus dem Credential-Endpoint).
     */
    _verifyProofOfPossession(jwtString) {
        const parts = jwtString.split('.');
        if (parts.length !== 3) {
            throw new Error('Ungültiges Proof-of-Possession-JWT Format.');
        }

        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        const signature = Buffer.from(parts[2], 'base64url');

        // 1. Typ-Prüfung
        if (header.typ !== 'openid4vci-proof+jwt') {
            throw new Error(`Ungültiger PoP-Typ: ${header.typ}`);
        }
        
        // 2. Audience- und Nonce-Prüfung (Zeitliche Freshness)
        if (payload.aud !== this.issuerId) {
            throw new Error(`Falsche Audience. Erwartet: ${this.issuerId}, erhalten: ${payload.aud}`);
        }

        if (payload.nonce) {
            const isNonceValid = this._validateAndConsumeNonce(payload.nonce);
            if (!isNonceValid) {
                throw new Error('PoP-Nonce ist abgelaufen oder ungültig.');
            }
        } else {
            throw new Error('Nonce fehlt im Proof of Possession Payload.');
        }

        // Schlüssel herleiten (JWK ist im Header enthalten)
        const holderJwk = header.jwk;
        if (!holderJwk) {
            throw new Error('Proof-Header enthält keinen eingebetteten jwk zur Signaturprüfung.');
        }

        const publicKey = crypto.createPublicKey({
            key: holderJwk,
            format: 'jwk'
        });

        const dataToVerify = `${parts[0]}.${parts[1]}`;
        const verify = crypto.createVerify('SHA256');
        verify.update(dataToVerify);

        if (!verify.verify(publicKey, signature)) {
            throw new Error('Die kryptografische PoP-Signatur ist ungültig.');
        }

        return holderJwk;
    }

    /**
     * Interner Validierungshelfer für WIA (Wallet Instance Attestation) & PoP.
     */
    _verifyWiaAndPop(wiaToken, wiaPop, expectedChallenge) {
        const wiaParts = wiaToken.split('.');
        const popParts = wiaPop.split('.');

        if (wiaParts.length !== 3 || popParts.length !== 3) {
            throw new Error('Ungültiges WIA- oder WIA-PoP-JWT Format.');
        }

        const wiaPayload = JSON.parse(Buffer.from(wiaParts[1], 'base64url').toString('utf8'));
        const popPayload = JSON.parse(Buffer.from(popParts[1], 'base64url').toString('utf8'));

        // 1. Signatur der WIA (durch das Wallet-Backend des Providers) verifizieren
        const wiaData = `${wiaParts[0]}.${wiaParts[1]}`;
        const wiaSig = Buffer.from(wiaParts[2], 'base64url');

        let isWiaVerified = false;
        for (const pemKey of this.trustedWalletKeys) {
            try {
                const verify = crypto.createVerify('SHA256');
                verify.update(wiaData);
                isWiaVerified = verify.verify(pemKey, wiaSig);
                if (isWiaVerified) break;
            } catch (err) {
                // Schlüssel durchprobieren
            }
        }

        if (!isWiaVerified) {
            throw new Error('WIA-Signaturprüfung gegen vertrauenswürdige Wallet-Provider fehlgeschlagen.');
        }

        // WIA-Schlüssel (wi_wia_pop_pubk) extrahieren
        const walletDeviceJwk = wiaPayload.cnf?.jwk;
        if (!walletDeviceJwk) {
            throw new Error('Die WIA enthält keinen eingebetteten Geräteschlüssel (cnf.jwk).');
        }

        // 2. Signatur des PoP-Tokens (durch die lokale Wallet-Instanz) verifizieren
        const popData = `${popParts[0]}.${popParts[1]}`;
        const popSig = Buffer.from(popParts[2], 'base64url');

        const devicePubKey = crypto.createPublicKey({
            key: walletDeviceJwk,
            format: 'jwk'
        });

        const popVerify = crypto.createVerify('SHA256');
        popVerify.update(popData);

        if (!popVerify.verify(devicePubKey, popSig)) {
            throw new Error('Die Signatur des WIA-Proofs (wia_pop) stimmt nicht mit dem Geräteschlüssel der WIA überein.');
        }

        // 3. Challenge-Vergleich zum Replay-Schutz
        if (expectedChallenge && popPayload.challenge !== expectedChallenge) {
            throw new Error('Sicherheitsfehler: Die WIA-Challenge stimmt nicht mit der erwarteten Challenge überein.');
        }

        return true;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AUSFÜHRBARES BEISPIEL UND END-TO-END DEMO-TEST
// ─────────────────────────────────────────────────────────────────────────────

if (require.main === module) {
    console.log('=== START EUDI WALLET ISSUANCE VERIFIER & PID ISSUER TEST ===\n');

    async function runDemo() {
        // 1. Schlüsselpaare erzeugen
        console.log('[Setup] Erzeuge kryptografische Schlüsselpaare...');
        const issuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const walletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const deviceKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); // Device Binding Key

        const issuerPrivatePem = issuerKeys.privateKey.export({ type: 'sec1', format: 'pem' });
        const issuerPublicPem = issuerKeys.publicKey.export({ type: 'spki', format: 'pem' });
        const walletPublicPem = walletKeys.publicKey.export({ type: 'spki', format: 'pem' });
        
        const deviceJwk = deviceKeys.publicKey.export({ format: 'jwk' });

        // 2. Instanziierung des EUDI PID Providers
        const pidProvider = new EUDIPIDIssuerVerifier({
            issuerId: 'https://pid-provider.bundesdruckerei.de',
            issuerPrivateKeyPem: issuerPrivatePem,
            issuerPublicKeyPem: issuerPublicPem,
            trustedWalletKeys: [walletPublicPem]
        });

        // 3. Erzeugen von Einmal-Nonces (für den Credential-Endpoint und DPoP)
        console.log('\n[Flow 1] Rufe Nonce-Endpoint auf...');
        const nonces = pidProvider.generateNonceResponse();
        console.log('Nonces erhalten:', JSON.stringify(nonces, null, 2));

        // 4. Token-Request simulieren (Mutual TLS, WIA und PKCE)
        console.log('\n[Flow 2] Simuliere WIA- & Token-Request-Verifikation...');
        
        // Mock WIA
        const wiaHeader = { alg: 'ES256', typ: 'oauth-client-attestation+jwt' };
        const wiaPayload = {
            iss: 'https://wallet-provider.de',
            sub: 'https://wallet.de/instances/456',
            cnf: { jwk: walletKeys.publicKey.export({ format: 'jwk' }) } // Wallet Public Key
        };
        const wiaData = `${Buffer.from(JSON.stringify(wiaHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(wiaPayload)).toString('base64url')}`;
        const wiaSign = crypto.createSign('SHA256'); wiaSign.update(wiaData);
        const wiaToken = `${wiaData}.${wiaSign.sign(walletKeys.privateKey, 'base64url')}`;

        // Mock WIA-PoP
        const wiaChallenge = 'challenge_123456789_test';
        const popHeader = { alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' };
        const popPayload = {
            iss: 'https://wallet-provider.de',
            aud: 'https://pid-provider.bundesdruckerei.de',
            challenge: wiaChallenge
        };
        const popData = `${Buffer.from(JSON.stringify(popHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(popPayload)).toString('base64url')}`;
        const popSign = crypto.createSign('SHA256'); popSign.update(popData);
        const wiaPop = `${popData}.${popSign.sign(walletKeys.privateKey, 'base64url')}`;

        // Mock DPoP Proof für Token-Schnittstelle
        const tokenDpopHeader = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletKeys.publicKey.export({ format: 'jwk' }) };
        const tokenDpopPayload = {
            htm: 'POST',
            htu: 'https://pid-provider.bundesdruckerei.de/token',
            nonce: nonces.dpop_nonce // Bindung an DPoP Nonce
        };
        const tokenDpopData = `${Buffer.from(JSON.stringify(tokenDpopHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(tokenDpopPayload)).toString('base64url')}`;
        const tokenDpopSign = crypto.createSign('SHA256'); tokenDpopSign.update(tokenDpopData);
        const tokenDpopProof = `${tokenDpopData}.${tokenDpopSign.sign(walletKeys.privateKey, 'base64url')}`;

        const tokenResult = pidProvider.verifyTokenRequest({
            code: 'auth_code_987654321',
            dpopProof: tokenDpopProof,
            wiaToken,
            wiaPop,
            expectedWiaChallenge: wiaChallenge
        });

        console.log('Ergebnis Token-Verifikation:', JSON.stringify(tokenResult, null, 2));

        // 5. Credential-Endpoint-Abfrage simulieren (Ausweis-Herausgabe)
        console.log('\n[Flow 3] Rufe Credential-Endpoint auf (Herausgabe-Verifikation)...');

        // Generiere neue Nonce für den Credential-Endpoint PoP
        const flow2Nonces = pidProvider.generateNonceResponse();

        // Mock DPoP Proof für Credential-Schnittstelle
        const credDpopHeader = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletKeys.publicKey.export({ format: 'jwk' }) };
        const credDpopPayload = {
            htm: 'POST',
            htu: 'https://pid-provider.bundesdruckerei.de/credential',
            nonce: flow2Nonces.dpop_nonce
        };
        const credDpopData = `${Buffer.from(JSON.stringify(credDpopHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(credDpopPayload)).toString('base64url')}`;
        const credDpopSign = crypto.createSign('SHA256'); credDpopSign.update(credDpopData);
        const credDpopProof = `${credDpopData}.${credDpopSign.sign(walletKeys.privateKey, 'base64url')}`;

        // Mock Schlüsselbesitznachweis (PoP) des Nutzers (Device Key)
        const popProofHeader = { alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: deviceJwk };
        const popProofPayload = {
            aud: 'https://pid-provider.bundesdruckerei.de',
            nonce: flow2Nonces.c_nonce // Bindung an Credential Nonce
        };
        const popProofData = `${Buffer.from(JSON.stringify(popProofHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(popProofPayload)).toString('base64url')}`;
        const popProofSign = crypto.createSign('SHA256'); popProofSign.update(popProofData);
        const popProofJwt = `${popProofData}.${popProofSign.sign(deviceKeys.privateKey, 'base64url')}`;

        const credRequest = {
            credential_configuration_id: 'PID_SD_JWT_VC',
            proofs: {
                jwt: popProofJwt
            }
        };

        const credResult = pidProvider.verifyCredentialRequest({
            credentialRequest: credRequest,
            dpopProof: credDpopProof,
            accessTokenPayload: {
                cnf: { jwk: walletKeys.publicKey.export({ format: 'jwk' }) } // sender-constrained Access-Token key
            }
        });

        console.log('Ergebnis Credential-Request-Verifikation:', JSON.stringify(credResult, null, 2));

        if (credResult.success) {
            console.log('\n[Flow 4] Generiere & Signiere Erika Mustermanns EUDI-Ausweis (PID)...');
            
            // Erika Mustermann Datensatz (PID-Claims)
            const erikaClaims = {
                given_name: 'Erika',
                family_name: 'Mustermann',
                birthdate: '1998-08-12',
                is_over_18: true,
                nationalities: ['DE'],
                address: {
                    street_address: 'Heidestraße 17',
                    locality: 'Köln',
                    postal_code: '50667',
                    country: 'DE'
                }
            };

            const signedCredentialString = pidProvider.issuePID({
                claims: erikaClaims,
                holderJwk: credResult.devicePublicKeyJwk
            });

            console.log('\n✅ AUSWEIS ERFOLGREICH AUSGESTELLT!');
            console.log('SD-JWT VC Token-String:');
            console.log(signedCredentialString);
        } else {
            console.error('\n❌ AUSSTELLUNG ABGEBROCHEN. Validierungsfehler aufgetreten.');
        }
    }

    runDemo().catch(console.error);
}

module.exports = { EUDIPIDIssuerVerifier };
