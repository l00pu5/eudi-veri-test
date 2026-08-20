/**
 * EUDI Wallet - Combined Relying Party (RP) & Credential Issuer REST API Server v2
 * 
 * Dieses Express-Modul implementiert die vollständigen Endpunkte für:
 * 1. Ein RP-Backend zur Präsentation von Credentials (OpenID4VP)
 * 2. Ein Issuer-Backend zur Ausstellung einer Muster-PID (OpenID4VCI v1.0 / HAIP 1.0)
 * 
 * Es verwendet das zuvor erstellte Validierungsmodul 'eudi-verifier-helper-v2.js' (RP)
 * und 'eudi-issuer-verifier.js' (Issuer).
 * 
 * Installation der benötigten Pakete:
 * npm install express express-session body-parser cors
 */

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const { EUDIVerifier } = require('./eudi-verifier-helper-v2');
const { EUDIPIDIssuerVerifier } = require('./eudi-issuer-verifier');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware konfigurieren
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session-Management zur Speicherung von Nonce und Verifizierungsergebnissen
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, maxAge: 300000 } // 5 Minuten Gültigkeit
}));

// In-Memory Speicher für transienten Status-Abgleich (Alternative zu Redis im Produktivbetrieb)
const transactionStore = new Map();
const accessTokenStore = new Map(); // token -> { dpopKey, claims }

// Konfiguration der Relying Party (Präsentation)
const RP_CONFIG = {
    clientId: 'x509_san_dns:client.example.org',
    publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`, // Dynamische Auflösung
    trustedIssuerKeys: [],
    trustedWalletKeys: []
};

// Konfiguration des Credential Issuers (Ausstellung)
const ISSUER_CONFIG = {
    issuerId: process.env.ISSUER_ID || `http://localhost:${PORT}/api/issuance`, // Dynamischer IssuerId passend zum Server-Host
    publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
    trustedWalletKeys: []
};

// Kryptografische Schlüssel für Demo-Betrieb generieren (simuliert Trust-Store / PKI)
let demoIssuerKeys, demoWalletKeys, rpSigningKeys;
try {
    demoIssuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    demoWalletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    rpSigningKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); // Zum Signieren des JARs

    // Trust-Stores befüllen
    RP_CONFIG.trustedIssuerKeys.push(demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }));
    RP_CONFIG.trustedWalletKeys.push(demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' }));
    ISSUER_CONFIG.trustedWalletKeys.push(demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' }));
} catch (e) {
    console.error('Fehler bei der Schlüsselgenerierung:', e);
}

// Instanziierung des EUDI PID Providers (Aussteller)
const pidIssuer = new EUDIPIDIssuerVerifier({
    issuerId: ISSUER_CONFIG.issuerId,
    issuerPrivateKeyPem: demoIssuerKeys.privateKey.export({ type: 'sec1', format: 'pem' }),
    issuerPublicKeyPem: demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }),
    trustedWalletKeys: ISSUER_CONFIG.trustedWalletKeys
});

// =============================================================================
// TEIL 1: SPREAD-ENDPOINTS FÜR PRÄSENTATION (OPENID4VP)
// =============================================================================

// ENDPUNKT 1: PRÄSENTATION INITIEREIN (QR-Code-Inhalt generieren)
app.get('/api/presentation/initiate', (req, res) => {
    const sessionId = 'session_' + crypto.randomBytes(12).toString('hex');
    const nonce = 'nonce_' + crypto.randomBytes(16).toString('hex');
    
    req.session.sessionId = sessionId;
    req.session.expectedNonce = nonce;
    req.session.verificationStatus = 'PENDING';

    transactionStore.set(sessionId, {
        type: 'PRESENTATION',
        nonce: nonce,
        status: 'PENDING',
        claims: null,
        errors: [],
        responseCode: null
    });

    const requestUri = `${RP_CONFIG.publicUrl}/api/presentation/request-jwt?sid=${sessionId}`;
    const qrCodeUrl = `openid4vp://?client_id=${encodeURIComponent(RP_CONFIG.clientId)}&request_uri=${encodeURIComponent(requestUri)}`;

    console.log(`[RP Server] Session initiiert. ID: ${sessionId}, Erwartete Nonce: ${nonce}`);

    res.json({
        success: true,
        sessionId: sessionId,
        qrCodeUrl: qrCodeUrl,
        pollEndpoint: `/api/presentation/status?sid=${sessionId}`
    });
});

// ENDPUNKT 2: REQUEST OBJECT (JAR) BEREITSTELLEN
app.get('/api/presentation/request-jwt', (req, res) => {
    const sessionId = req.query.sid;
    
    if (!sessionId || !transactionStore.has(sessionId)) {
        return res.status(400).json({ error: 'Ungültige oder abgelaufene Transaktions-ID' });
    }

    const tx = transactionStore.get(sessionId);

    const dcqlQuery = {
        credentials: [
            {
                id: "my_identity_credential",
                format: "dc+sd-jwt",
                meta: {
                    vct_values: ["https://credentials.example.com/identity_credential"]
                },
                claims: [
                    { "path": ["given_name"] },
                    { "path": ["family_name"] },
                    { "path": ["birthdate"] },
                    { "path": ["is_over_18"] },
                    { "path": ["address"] }
                ]
            }
        ]
    };

    const requestPayload = {
        iss: RP_CONFIG.clientId,
        aud: "https://self-issued.me/v2",
        response_type: "vp_token",
        response_mode: "direct_post",
        response_uri: `${RP_CONFIG.publicUrl}/api/presentation/callback`,
        client_id: RP_CONFIG.clientId,
        nonce: tx.nonce,
        state: sessionId,
        dcql_query: dcqlQuery
    };

    const jwtHeader = {
        alg: 'ES256',
        typ: 'oauth-authz-req+jwt'
    };

    try {
        const tokenInput = `${Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(requestPayload)).toString('base64url')}`;
        const signer = crypto.createSign('SHA256');
        signer.update(tokenInput);
        const signature = signer.sign(rpSigningKeys.privateKey, 'base64url');
        const signedJwt = `${tokenInput}.${signature}`;

        console.log(`[RP Server] JAR-Request für Session ${sessionId} an Wallet ausgeliefert.`);

        res.setHeader('Content-Type', 'application/oauth-authz-req+jwt');
        res.setHeader('Cache-Control', 'no-store');
        res.send(signedJwt);
    } catch (err) {
        console.error('JAR Signierungsfehler:', err);
        res.status(500).json({ error: 'Kryptografischer Serverfehler beim Erzeugen des JAR' });
    }
});

// ENDPUNKT 3: DIRECT_POST CALLBACK
app.post('/api/presentation/callback', async (req, res) => {
    const { vp_token, state, wia_token } = req.body;

    console.log(`[RP Server] direct_post Callback erhalten. State (Session-ID): ${state}`);

    if (!state || !transactionStore.has(state)) {
        return res.status(400).json({ error: 'Transaktions-Kontext fehlt oder abgelaufen' });
    }

    const tx = transactionStore.get(state);

    try {
        let parsedVpToken;
        try {
            parsedVpToken = JSON.parse(vp_token);
        } catch (e) {
            parsedVpToken = JSON.parse(decodeURIComponent(vp_token));
        }

        const verifier = new EUDIVerifier({
            clientId: RP_CONFIG.clientId,
            expectedNonce: tx.nonce,
            trustedIssuerKeys: RP_CONFIG.trustedIssuerKeys,
            trustedWalletKeys: RP_CONFIG.trustedWalletKeys
        });

        console.log(`[RP Server] Starte 4-Säulen-Validierung für Session: ${state}...`);
        const verificationResult = await verifier.verifyPresentation(parsedVpToken, wia_token);

        if (verificationResult.success) {
            console.log(`[RP Server] ✅ Verifizierung erfolgreich! Claims für ${state} extrahiert.`);
            
            const responseCode = crypto.randomBytes(16).toString('hex');
            tx.status = 'SUCCESS';
            tx.claims = verificationResult.claims;
            tx.responseCode = responseCode;
            transactionStore.set(state, tx);

            res.status(200).json({
                redirect_uri: `${RP_CONFIG.publicUrl}/login-success.html?sid=${state}&code=${responseCode}`
            });
        } else {
            console.error(`[RP Server] ❌ Verifizierung fehlgeschlagen:`, verificationResult.errors);
            tx.status = 'FAILED';
            tx.errors = verificationResult.errors;
            transactionStore.set(state, tx);

            res.status(400).json({ error: 'Kryptografische 4-Säulen-Verifizierung fehlgeschlagen.' });
        }
    } catch (err) {
        console.error('Interner direct_post Fehler:', err);
        tx.status = 'FAILED';
        tx.errors.push(err.message);
        transactionStore.set(state, tx);
        res.status(500).json({ error: 'Interner Serverfehler im direct_post Callback' });
    }
});

// ENDPUNKT 4: STATUS POLLING FÜR FRONTEND
app.get('/api/presentation/status', (req, res) => {
    const sessionId = req.query.sid;

    if (!sessionId || !transactionStore.has(sessionId)) {
        return res.status(404).json({ success: false, status: 'NOT_FOUND', error: 'Ungültige Sitzung' });
    }

    const tx = transactionStore.get(sessionId);

    if (tx.status === 'SUCCESS') {
        return res.json({
            success: true,
            status: 'SUCCESS',
            claims: tx.claims,
            responseCode: tx.responseCode
        });
    } else if (tx.status === 'FAILED') {
        return res.json({
            success: false,
            status: 'FAILED',
            errors: tx.errors
        });
    }

    res.json({
        success: true,
        status: 'PENDING'
    });
});

// =============================================================================
// TEIL 2: ENDPOINTS FÜR AUSSTELLUNG & BELEGVALIDIERUNG (OPENID4VCI)
// =============================================================================

// AUSSTELLUNG 1: INITIEREIN (Gibt ein Credential-Offer zurück)
app.get('/api/issuance/initiate', (req, res) => {
    const sessionId = 'session_iss_' + crypto.randomBytes(12).toString('hex');
    const wiaChallenge = 'challenge_iss_' + crypto.randomBytes(16).toString('hex');
    
    // In-Memory registrieren
    transactionStore.set(sessionId, {
        type: 'ISSUANCE',
        wiaChallenge: wiaChallenge,
        status: 'PENDING'
    });

    const issuerUrl = `${ISSUER_CONFIG.publicUrl}/api/issuance`;
    const offerObj = {
        credential_issuer: issuerUrl,
        credential_configuration_ids: ['PID_SD_JWT_VC'],
        grants: {
            authorization_code: {
                issuer_state: sessionId
            }
        }
    };

    const offerUrl = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offerObj))}`;
    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(offerUrl)}`;

    console.log(`[Issuer Server] Issuance Session initiiert. Challenge: ${wiaChallenge}`);

    res.json({
        success: true,
        sessionId: sessionId,
        wiaChallenge: wiaChallenge,
        credentialOfferUrl: offerUrl,
        qrCodeUrl: qrCodeUrl
    });
});

// AUSSTELLUNG 2: WELL-KNOWN METADATEN
app.get('/api/issuance/.well-known/openid-credential-issuer', (req, res) => {
    const issuerUrl = `${ISSUER_CONFIG.publicUrl}/api/issuance`;
    const metadata = {
        credential_issuer: issuerUrl,
        authorization_servers: [ `${ISSUER_CONFIG.publicUrl}/api/issuance` ],
        credential_endpoint: `${issuerUrl}/credential`,
        nonce_endpoint: `${issuerUrl}/nonce`,
        credential_configurations_supported: {
            "PID_SD_JWT_VC": {
                format: "dc+sd-jwt",
                scope: "PID_SD_JWT_VC",
                credential_signing_alg_values_supported: ["ES256"],
                cryptographic_binding_methods_supported: ["jwk"],
                proof_types_supported: {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"],
                        "key_attestations_required": {
                            "key_storage": ["iso_18045_moderate"],
                            "user_authentication": ["iso_18045_moderate"]
                        }
                    }
                },
                vct: "https://credentials.example.com/identity_credential",
                credential_metadata: {
                    display: [
                        {
                            name: "Muster Personenidentifikationsnachweis (PID)",
                            locale: "de-DE",
                            background_color: "#0B192C",
                            text_color: "#FFFFFF"
                        }
                    ]
                }
            }
        }
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.json(metadata);
});

// AUSSTELLUNG 3: NONCE ENDPOINT
app.post('/api/issuance/nonce', (req, res) => {
    console.log('[Issuer Server] Nonce Request erhalten.');
    const nonces = pidIssuer.generateNonceResponse();
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.json(nonces);
});

// AUSSTELLUNG 4: TOKEN ENDPOINT (DPoP- & WIA-Verifikation)
app.post('/api/issuance/token', (req, res) => {
    console.log('[Issuer Server] Token Request erhalten.');
    
    const { code, code_verifier, client_assertion, client_assertion_pop, wia_challenge_sid } = req.body;
    const dpopProof = req.headers['dpop'];

    let expectedWiaChallenge = null;
    if (wia_challenge_sid && transactionStore.has(wia_challenge_sid)) {
        expectedWiaChallenge = transactionStore.get(wia_challenge_sid).wiaChallenge;
    }

    const tokenResult = pidIssuer.verifyTokenRequest({
        code: code,
        codeVerifier: code_verifier,
        dpopProof: dpopProof,
        wiaToken: client_assertion,
        wiaPop: client_assertion_pop,
        expectedWiaChallenge: expectedWiaChallenge
    });

    if (tokenResult.success) {
        console.log('[Issuer Server] ✅ Token-Request erfolgreich verifiziert. Generiere Access Token...');
        
        const accessToken = 'access_token_' + crypto.randomBytes(16).toString('hex');
        const nonceResponse = pidIssuer.generateNonceResponse();
        
        // Speichere Token-Kontext für den Credential-Endpoint-Abruf
        accessTokenStore.set(accessToken, {
            dpopKey: tokenResult.dpopKey,
            scope: 'PID_SD_JWT_VC'
        });

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'no-store');
        res.json({
            access_token: accessToken,
            token_type: 'DPoP',
            expires_in: 3600,
            c_nonce: nonceResponse.c_nonce,
            c_nonce_expires_in: nonceResponse.c_nonce_expires_in
        });
    } else {
        console.error('[Issuer Server] ❌ Token-Verifikation fehlgeschlagen:', tokenResult.errors);
        res.status(400).json({
            error: 'invalid_request',
            error_description: tokenResult.errors.join(', ')
        });
    }
});

// AUSSTELLUNG 5: CREDENTIAL ENDPOINT (Ausgabe-Verifikation & Ausstellung)
app.post('/api/issuance/credential', (req, res) => {
    console.log('[Issuer Server] Credential Request erhalten.');

    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('DPoP ')) {
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'DPoP Access Token im Authorization Header erforderlich.'
        });
    }
    const accessToken = authHeader.substring(5);
    const tokenData = accessTokenStore.get(accessToken);

    if (!tokenData) {
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Ungültiges, abgelaufenes oder unbekanntes Access Token.'
        });
    }

    const dpopProof = req.headers['dpop'];
    const credentialRequest = req.body;

    const credResult = pidIssuer.verifyCredentialRequest({
        credentialRequest: credentialRequest,
        dpopProof: dpopProof,
        accessTokenPayload: {
            cnf: { jwk: tokenData.dpopKey }
        }
    });

    if (credResult.success) {
        console.log('[Issuer Server] ✅ Belegbesitz-Verifikation erfolgreich. Erzeuge SD-JWT VC...');
        
        // Erika Mustermann standardmäßiger PID-Datensatz
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

        const signedPid = pidIssuer.issuePID({
            claims: erikaClaims,
            holderJwk: credResult.devicePublicKeyJwk
        });

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'no-store');
        res.json({
            credentials: [
                {
                    credential: signedPid
                }
            ]
        });
    } else {
        console.error('[Issuer Server] ❌ Belegbesitz-Verifikation fehlgeschlagen:', credResult.errors);
        res.status(400).json({
            error: 'invalid_proof',
            error_description: credResult.errors.join(', ')
        });
    }
});

// Starten des API-Servers
app.listen(PORT, () => {
    console.log(`\n=== EUDI WALLET INTEGRATED SERVER (PRESENTATION & ISSUANCE) ===`);
    console.log(`Server läuft lokal auf: http://localhost:${PORT}`);
    console.log(`Öffentliche RP-Identität (client_id): ${RP_CONFIG.clientId}`);
    console.log(`Öffentliche Issuer-Identität (issuer_id): ${ISSUER_CONFIG.issuerId}`);
    console.log(`Werte auf Wallet-Verbindungen (Präsentation und Ausstellung)...\\n`);
});

module.exports = app;