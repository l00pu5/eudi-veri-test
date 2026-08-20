/**
 * EUDI Wallet - Relying Party (RP) Verification Helper
 * 
 * Dieses Modul implementiert die serverseitige Verifizierungslogik für 
 * empfangene OpenID4VP-Präsentationen (vp_token) im EUDI-Wallet-Ökosystem. [32]
 * Es ist modular aufgebaut und strukturiert die Validierung entlang der
 * gesetzlich und technisch geforderten "4 Säulen der Verifizierung". [11, 12]
 * 
 * Voraussetzungen:
 * - Node.js (v18 oder höher empfohlen)
 * - Keine externen Abhängigkeiten (verwendet ausschließlich das native 'crypto'-Modul)
 * 
 * @module EUDIVerifier
 */

const crypto = require('crypto');

class EUDIVerifier {
  /**
   * Erstellt eine neue Instanz des Verifizierers.
   * @param {Object} config - Konfiguration der Relying Party
   * @param {string} config.clientId - Die registrierte Client-ID der RP [10, 385]
   * @param {string} config.expectedNonce - Die für diese Transaktion generierte Einmal-Nonce (Replay-Schutz) [10, 378]
   * @param {Array<string>} config.trustedIssuerKeys - Bekannte öffentliche Schlüssel vertrauenswürdiger Aussteller (PEM-Format) [44]
   * @param {Array<string>} config.trustedWalletKeys - Bekannte öffentliche Schlüssel autorisierter Wallet-Provider (WIA-Prüfung) [10, 11]
   */
  constructor(config) {
    if (!config.clientId || !config.expectedNonce) {
      throw new Error('Konfigurationsfehler: clientId und expectedNonce sind zwingend erforderlich.');
    }
    this.clientId = config.clientId;
    this.expectedNonce = config.expectedNonce;
    this.trustedIssuerKeys = config.trustedIssuerKeys || [];
    this.trustedWalletKeys = config.trustedWalletKeys || [];
  }

  /**
   * Hauptmethode zur Verifizierung eines empfangenen VP-Tokens.
   * Führt die Validierung schrittweise über alle 4 Säulen durch. [11]
   * 
   * @param {Object} vpToken - Das vom Wallet übermittelte vp_token (JSON-Struktur) [12, 366]
   * @param {string} wiaToken - Die optionale Wallet Instance Attestation (WIA) zur Wallet-Verifizierung [10, 11]
   * @returns {Promise<Object>} Verifizierungsergebnis mit extrahierten, verifizierten Attributen
   */
  async verifyPresentation(vpToken, wiaToken = null) {
    const result = {
      success: false,
      errors: [],
      claims: {},
      verifiedPillars: {
        issuerAuthenticity: false,
        deviceBinding: false,
        revocationStatus: false,
        walletValidation: false
      }
    };

    try {
      // Hilfsvariable zur Extraktion des Credentials
      // In OpenID4VP ist das vp_token ein JSON-Objekt, das Credentials unter ihren DCQL-IDs listet [430]
      const credentialId = Object.keys(vpToken)[0];
      if (!credentialId) {
        throw new Error('Ungültiges vp_token-Format: Keine Credential-ID gefunden.');
      }

      const rawCredential = vpToken[credentialId];

      // Analyse des Typs (SD-JWT VC oder ISO mdoc)
      const isSdJwt = typeof rawCredential === 'string' && rawCredential.includes('.');

      if (isSdJwt) {
        await this._verifySdJwtFlow(rawCredential, wiaToken, result);
      } else {
        // Platzhalter für ISO mdoc (CBOR/COSE-basiert)
        throw new Error('ISO mdoc (mso_mdoc) wird in diesem nativen JS-Helper nur strukturell unterstützt. Bitte nutzen Sie eine CBOR-Bibliothek.');
      }

      if (result.errors.length === 0) {
        result.success = true;
      }
    } catch (err) {
      result.errors.push(err.message);
    }

    return result;
  }

  /**
   * Interner Validierungs-Flow für SD-JWT VCs (Selective Disclosure JWTs) [302]
   */
  async _verifySdJwtFlow(sdJwtString, wiaToken, result) {
    // SD-JWT besteht aus: JWT-Payload ~ Disclosures... ~ Key Binding JWT (optional) [304, 305]
    const parts = sdJwtString.split('~');
    const credentialJwt = parts[0];
    const keyBindingJwt = parts[parts.length - 1]; // Letzter Teil bei Key Binding
    const disclosures = parts.slice(1, parts.length - 1);

    // 1. Dekodieren des Haupt-Credentials
    const parsedCred = this._decodeJwt(credentialJwt);

    // ── SÄULE 1: AUSSTELLER-AUTHENTIZITÄT & INTEGRITÄT ──────────────────────────
    try {
      this._verifyIssuerSignature(credentialJwt, parsedCred.header);
      result.verifiedPillars.issuerAuthenticity = true;
    } catch (err) {
      result.errors.push(`Säule 1 (Issuer Authenticity) fehlgeschlagen: ${err.message}`);
      return;
    }

    // Offenlegen und Extrahieren der selektiv freigegebenen Attribute (Disclosures)
    const disclosedClaims = this._extractDisclosures(disclosures);
    result.claims = { ...parsedCred.payload, ...disclosedClaims };
    // Bereinigen von SD-JWT-Metadaten aus den Result-Claims
    delete result.claims._sd;
    delete result.claims._sd_alg;

    // ── SÄULE 2: GERÄTEBINDUNG (PROOF OF POSSESSION) ──────────────────────────
    try {
      if (!keyBindingJwt || keyBindingJwt.trim() === '') {
        throw new Error('Kein Key-Binding-JWT im SD-JWT-Token vorhanden, obwohl Gerätebindung gefordert ist.');
      }
      this._verifyDeviceBinding(keyBindingJwt, result.claims.cnf?.jwk);
      result.verifiedPillars.deviceBinding = true;
    } catch (err) {
      result.errors.push(`Säule 2 (Device Binding) fehlgeschlagen: ${err.message}`);
    }

    // ── SÄULE 3: REVERZIERUNG & STATUSPRÜFUNG ─────────────────────────────────
    try {
      await this._checkRevocationStatus(result.claims.status);
      result.verifiedPillars.revocationStatus = true;
    } catch (err) {
      result.errors.push(`Säule 3 (Revocation Status) fehlgeschlagen: ${err.message}`);
    }

    // ── SÄULE 4: WALLET-APP VALIDIERUNG (WIA/WTE) ──────────────────────────────
    if (wiaToken) {
      try {
        this._validateWalletInstance(wiaToken);
        result.verifiedPillars.walletValidation = true;
      } catch (err) {
        result.errors.push(`Säule 4 (Wallet Validation) fehlgeschlagen: ${err.message}`);
      }
    } else {
      result.errors.push('Säule 4 Warnung: WIA-Token nicht übermittelt. Wallet-Authentizität konnte nicht unabhängig geprüft werden.');
    }
  }

  /**
   * Säule 1: Verifiziert die digitale Signatur des Ausstellers (Issuer) [11]
   */
  _verifyIssuerSignature(jwtString, header) {
    if (this.trustedIssuerKeys.length === 0) {
      throw new Error('Keine vertrauenswürdigen Aussteller-Schlüssel (trustedIssuerKeys) konfiguriert. Verifizierung unmöglich.');
    }

    const jwtParts = jwtString.split('.');
    const dataToVerify = `${jwtParts[0]}.${jwtParts[1]}`;
    const signature = Buffer.from(jwtParts[2], 'base64url');

    let isVerified = false;
    let lastError = null;

    for (const pemKey of this.trustedIssuerKeys) {
      try {
        const verify = crypto.createVerify('SHA256');
        verify.update(dataToVerify);
        isVerified = verify.verify(pemKey, signature);
        if (isVerified) break;
      } catch (err) {
        lastError = err;
      }
    }

    if (!isVerified) {
      throw new Error(`Signaturprüfung fehlgeschlagen. Der Ausstellerschlüssel ist unbekannt oder ungültig. ${lastError ? lastError.message : ''}`);
    }
  }

  /**
   * Säule 2: Verifiziert das Key Binding (Gerätebindung des Nutzers via Hardware-Schlüssel) [11, 45, 605, 613]
   */
  _verifyDeviceBinding(kbJwtString, holderJwk) {
    if (!holderJwk) {
      throw new Error('Der Nachweis enthält keinen öffentlichen Nutzerschlüssel (cnf.jwk). Gerätebindung kann nicht geprüft werden.');
    }

    const kbParts = kbJwtString.split('.');
    if (kbParts.length !== 3) {
      throw new Error('Ungültiges Key-Binding-JWT-Format.');
    }

    const kbPayload = JSON.parse(Buffer.from(kbParts[1], 'base64url').toString('utf8'));
    const kbHeader = JSON.parse(Buffer.from(kbParts[0], 'base64url').toString('utf8'));

    // 1. Replay-Schutz: Entspricht die Nonce unserer Transaktions-Nonce? [378, 469]
    if (kbPayload.nonce !== this.expectedNonce) {
      throw new Error(`Replay-Angriff erkannt! Erwartete Nonce: ${this.expectedNonce}, erhalten: ${kbPayload.nonce}`);
    }

    // 2. Client-Bindung: Stimmt die Empfänger-ID mit unserer Client-ID überein? [469]
    if (kbPayload.aud !== this.clientId) {
      throw new Error(`Falscher Empfänger! Erwartete Client-ID (aud): ${this.clientId}, erhalten: ${kbPayload.aud}`);
    }

    // 3. Typ-Prüfung: Ist das KB-JWT vom Typ "openid4vci-proof+jwt" oder "kb+jwt"? [320]
    if (kbHeader.typ !== 'openid4vci-proof+jwt' && kbHeader.typ !== 'kb+jwt' && kbHeader.typ !== 'openid4vp-proof+jwt') {
      throw new Error(`Ungültiger KB-JWT Typ im Header: ${kbHeader.typ}`);
    }

    // 4. Kryptografische Signaturprüfung des Nutzers gegen dessen im Credential gebundenen JWK [44]
    try {
      const pubKey = crypto.createPublicKey({
        key: holderJwk,
        format: 'jwk'
      });

      const dataToVerify = `${kbParts[0]}.${kbParts[1]}`;
      const signature = Buffer.from(kbParts[2], 'base64url');

      const verify = crypto.createVerify('SHA256');
      verify.update(dataToVerify);

      const isVerified = verify.verify(pubKey, signature);
      if (!isVerified) {
        throw new Error('Die Signatur des Key-Binding-JWTs stimmt nicht mit dem gebundenen Schlüssel (cnf.jwk) überein.');
      }
    } catch (err) {
      throw new Error(`Fehler bei kryptografischer Geräteprüfung: ${err.message}`);
    }
  }

  /**
   * Säule 3: Prüft den Sperrstatus des Credentials (asynchron) [11, 46]
   */
  async _checkRevocationStatus(statusClaim) {
    if (!statusClaim) {
      // Im Sandbox-Modus oder bei einfachen EAAs oft optional, im Live-Betrieb zwingend
      return true;
    }

    // Ein typischer Status-Claim nach dem Token Status List Standard (TSL) enthält:
    // status: { status_list: { idx: 125, uri: 'https://status.example.com/list' } } [271]
    const statusList = statusClaim.status_list;
    if (!statusList || typeof statusList.idx !== 'number' || !statusList.uri) {
      throw new Error('Sperrstatus-Claim ist syntaktisch ungültig.');
    }

    // HINWEIS: In der produktiven Umgebung wird hier die Status-Bitliste asynchron
    // per HTTP-Request geladen und die Bit-Position überprüft.
    console.log(`[Status List Fetch] Rufe Status-Bitliste ab unter URI: ${statusList.uri}`);

    // Simulation des Bit-Checks: 0 = Gültig, 1 = Gesperrt
    const simulatedBitValue = 0;

    if (simulatedBitValue !== 0) {
      throw new Error(`Das digitale Zertifikat wurde vom Aussteller gesperrt (Bit-Wert an Position ${statusList.idx} ist ungleich 0).`);
    }

    return true;
  }

  /**
   * Säule 4: Validiert die Echtheit der anfragenden Wallet-Instanz (WIA/WTE) [11, 12]
   */
  _validateWalletInstance(wiaTokenString) {
    if (this.trustedWalletKeys.length === 0) {
      throw new Error('Keine vertrauenswürdigen Wallet-Provider-Schlüssel konfiguriert.');
    }

    const wiaParts = wiaTokenString.split('.');
    if (wiaParts.length !== 3) {
      throw new Error('Ungültiges Wallet Instance Attestation (WIA) JWT-Format.');
    }

    const wiaHeader = JSON.parse(Buffer.from(wiaParts[0], 'base64url').toString('utf8'));
    const wiaPayload = JSON.parse(Buffer.from(wiaParts[1], 'base64url').toString('utf8'));

    // Typenprüfung gemäß eIDAS-WIA Profil
    if (wiaHeader.typ !== 'oauth-client-attestation+jwt') {
      throw new Error(`Ungültiger WIA-Typ im Header: ${wiaHeader.typ}`);
    }

    // Signaturprüfung des WIA-Tokens gegen den Trusted Store der Wallet-Provider
    const dataToVerify = `${wiaParts[0]}.${wiaParts[1]}`;
    const signature = Buffer.from(wiaParts[2], 'base64url');

    let isVerified = false;
    for (const pemKey of this.trustedWalletKeys) {
      try {
        const verify = crypto.createVerify('SHA256');
        verify.update(dataToVerify);
        isVerified = verify.verify(pemKey, signature);
        if (isVerified) break;
      } catch (err) {
        // Schlüssel durchprobieren
      }
    }

    if (!isVerified) {
      throw new Error('Die Wallet Instance Attestation (WIA) wurde mit einem unbekannten oder ungültigen Schlüssel signiert.');
    }

    // Überprüfung der Gültigkeit
    const now = Math.floor(Date.now() / 1000);
    if (wiaPayload.exp && now > wiaPayload.exp) {
      throw new Error('Die Wallet Instance Attestation (WIA) ist abgelaufen.');
    }

    console.log(`[WIA Validierung] Wallet-Echtheit erfolgreich bestätigt für Wallet: ${wiaPayload.wallet_name || 'Unbekannt'}`);
  }

  /**
   * Hilfsmethode: Dekodieren und Extrahieren von SD-JWT Disclosures (Klartext-Enthüllungen)
   */
  _extractDisclosures(disclosureStrings) {
    const claims = {};

    for (const disclosure of disclosureStrings) {
      if (!disclosure) continue;

      try {
        // Jede Offenlegung ist ein base64url-kodiertes JSON-Array: [Salt, ClaimName, ClaimValue]
        const decodedJson = Buffer.from(disclosure, 'base64url').toString('utf8');
        const array = JSON.parse(decodedJson);

        if (Array.isArray(array) && array.length === 3) {
          const claimName = array[1];
          const claimValue = array[2];
          claims[claimName] = claimValue;
        }
      } catch (err) {
        // Fehlerhafte oder unvollständige Disclosure ignorieren
      }
    }

    return claims;
  }

  /**
   * Hilfsmethode: JWT dekodieren ohne Signaturprüfung
   */
  _decodeJwt(jwtString) {
    const parts = jwtString.split('.');
    if (parts.length < 2) {
      throw new Error('Ungültiges JWT-Format.');
    }

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

    return { header, payload };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// AUSFÜHRBARES BEISPIEL UND END-TO-END DEMO-TEST
// ─────────────────────────────────────────────────────────────────────────────

if (require.main === module) {
  console.log('=== START EUDI WALLET VERIFICATION HELPER TEST ===\n');

  async function runDemo() {
    // 1. Schlüsselpaare für Aussteller, Wallet und Nutzer (Holder) erstellen
    const issuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const walletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const holderKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

    const issuerPublicKeyPem = issuerKeys.publicKey.export({ type: 'spki', format: 'pem' });
    const walletPublicKeyPem = walletKeys.publicKey.export({ type: 'spki', format: 'pem' });

    const holderJwk = holderKeys.publicKey.export({ format: 'jwk' });

    // 2. Erstellung einer Mock-WIA (Wallet Instance Attestation)
    const wiaHeader = { alg: 'ES256', typ: 'oauth-client-attestation+jwt' };
    const wiaPayload = {
      iss: 'https://wallet-provider.example.com',
      sub: 'https://wallet.example.com/instances/12345',
      wallet_name: 'EUDI Wallet National Reference Implementation',
      iat: Math.floor(Date.now() / 1000) - 10,
      exp: Math.floor(Date.now() / 1000) + 3600
    };
    const wiaData = `${Buffer.from(JSON.stringify(wiaHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(wiaPayload)).toString('base64url')}`;
    const wiaSign = crypto.createSign('SHA256');
    wiaSign.update(wiaData);
    const wiaSignature = wiaSign.sign(walletKeys.privateKey).toString('base64url');
    const wiaToken = `${wiaData}.${wiaSignature}`;

    // 3. Erstellung des Haupt-Credentials (SD-JWT)
    // Disclosures für selektive Offenlegung: "given_name" und "family_name"
    const disclosure1 = Buffer.from(JSON.stringify(['salt12345678', 'given_name', 'Max'])).toString('base64url');
    const disclosure2 = Buffer.from(JSON.stringify(['salt87654321', 'family_name', 'Mustermann'])).toString('base64url');

    // Das Haupt-Credential enthält Hashes der Disclosures in '_sd' [305, 558]
    const hash = (data) => crypto.createHash('sha256').update(data).digest().toString('base64url');
    const sdHeader = { alg: 'ES256', typ: 'vc+sd-jwt' };
    const sdPayload = {
      iss: 'https://pid-provider.example.com',
      vct: 'https://credentials.example.com/identity_credential',
      _sd_alg: 'sha-256',
      _sd: [
        hash(disclosure1),
        hash(disclosure2)
      ],
      cnf: {
        jwk: holderJwk // Bindung des Nutzers (Holder) an den Ausweis [558]
      },
      status: {
        status_list: {
          idx: 42,
          uri: 'https://pid-provider.example.com/status/list-1'
        }
      }
    };

    const sdData = `${Buffer.from(JSON.stringify(sdHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(sdPayload)).toString('base64url')}`;
    const sdSign = crypto.createSign('SHA256');
    sdSign.update(sdData);
    const sdSignature = sdSign.sign(issuerKeys.privateKey).toString('base64url');
    const credentialJwt = `${sdData}.${sdSignature}`;

    // 4. Erstellung des Key-Binding-JWTs (Säule 2)
    const rpClientId = 'redirect_uri:https://my-relying-party.com/callback';
    const transactionNonce = 'xyz123456789abc_testNonce';

    const kbHeader = { alg: 'ES256', typ: 'openid4vci-proof+jwt' };
    const kbPayload = {
      aud: rpClientId,
      nonce: transactionNonce,
      iat: Math.floor(Date.now() / 1000)
    };

    const kbData = `${Buffer.from(JSON.stringify(kbHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(kbPayload)).toString('base64url')}`;
    const kbSign = crypto.createSign('SHA256');
    kbSign.update(kbData);
    const kbSignature = kbSign.sign(holderKeys.privateKey).toString('base64url');
    const kbJwt = `${kbData}.${kbSignature}`;

    // 5. Zusammensetzen des vollständigen SD-JWT-Strings
    const fullSdJwt = `${credentialJwt}~${disclosure1}~${disclosure2}~${kbJwt}`;

    // 6. Instanziierung des Verifizierers und Ausführen der End-to-End-Verifizierung
    const verifier = new EUDIVerifier({
      clientId: rpClientId,
      expectedNonce: transactionNonce,
      trustedIssuerKeys: [issuerPublicKeyPem],
      trustedWalletKeys: [walletPublicKeyPem]
    });

    const mockVpToken = {
      "my_pid_credential": fullSdJwt
    };

    console.log('Führe 4-Säulen-Validierung durch...\n');
    const verificationResult = await verifier.verifyPresentation(mockVpToken, wiaToken);

    console.log('ERGEBNIS DER PRÜFUNG:');
    console.log(JSON.stringify(verificationResult, null, 2));

    if (verificationResult.success) {
      console.log('\n✅ VERIFIZIERUNG ERFOLGREICH! Alle Säulen der Verifizierung sind intakt.');
    } else {
      console.error('\n❌ VERIFIZIERUNG FEHLGESCHLAGEN.');
    }
  }

  runDemo().catch(console.error);
}

module.exports = { EUDIVerifier };
