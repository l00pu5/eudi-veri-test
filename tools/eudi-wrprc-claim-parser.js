/**
 * EUDI Wallet - WRPRC Claims & Credentials Inspector Tool
 * 
 * Parses a WRPRC and extracts all credentials / claims that are declared
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

const STANDARD_CREDENTIAL_SCHEMAS = {
  'urn:eudi:pid:de:1': {
    name: 'Deutsche Personal Identification Data (PID / SD-JWT VC)',
    format: 'dc+sd-jwt',
    namespace: 'Top-Level Claims',
    standardClaims: [
      { path: 'family_name', desc: 'Nachname des Inhabers' },
      { path: 'given_name', desc: 'Vorname(n) des Inhabers' },
      { path: 'birth_date', desc: 'Geburtsdatum (YYYY-MM-DD)' },
      { path: 'age_over_18', desc: 'Altersbestaetigung 18+ (Boolean)' },
      { path: 'age_over_21', desc: 'Altersbestaetigung 21+ (Boolean)' },
      { path: 'age_in_years', desc: 'Aktuelles Alter in Jahren' },
      { path: 'place_of_birth', desc: 'Geburtsort' },
      { path: 'nationalities', desc: 'Staatsangehoerigkeit(en) (ISO 3166-1)' },
      { path: 'address_data', desc: 'Wohnanschrift (Strasse, Hausnummer, PLZ, Ort)' },
      { path: 'issuing_country', desc: 'Ausstellender Staat (z. B. DE)' },
      { path: 'issuing_authority', desc: 'Ausstellende Behoerde' },
      { path: 'document_number', desc: 'Ausweisnummer' },
      { path: 'issuance_date', desc: 'Ausstellungsdatum' },
      { path: 'expiry_date', desc: 'Ablaufdatum des Ausweises' }
    ]
  },
  'eu.europa.ec.eudi.pid.1': {
    name: 'European / German PID (ISO mdoc)',
    format: 'mso_mdoc',
    namespace: 'eu.europa.ec.eudi.pid.1',
    standardClaims: [
      { path: 'family_name', desc: 'Nachname des Inhabers' },
      { path: 'given_name', desc: 'Vorname(n) des Inhabers' },
      { path: 'birth_date', desc: 'Geburtsdatum (YYYY-MM-DD)' },
      { path: 'age_over_18', desc: 'Altersbestaetigung 18+ (Boolean)' },
      { path: 'age_over_21', desc: 'Altersbestaetigung 21+ (Boolean)' },
      { path: 'age_in_years', desc: 'Aktuelles Alter in Jahren' },
      { path: 'place_of_birth', desc: 'Geburtsort' },
      { path: 'nationality', desc: 'Staatsangehoerigkeit (ISO 3166-1)' },
      { path: 'resident_address', desc: 'Wohnadresse' },
      { path: 'resident_city', desc: 'Wohnort' },
      { path: 'resident_postal_code', desc: 'Postleitzahl' },
      { path: 'resident_country', desc: 'Wohnsitzland' },
      { path: 'issuing_country', desc: 'Ausstellungsland' },
      { path: 'issuing_authority', desc: 'Ausstellende Behoerde' },
      { path: 'document_number', desc: 'Ausweisnummer' },
      { path: 'issue_date', desc: 'Ausstellungsdatum' },
      { path: 'expiry_date', desc: 'Ablaufdatum' }
    ]
  },
  'org.iso.18013.5.1.mDL': {
    name: 'Mobile Driving License (mDL / ISO mdoc)',
    format: 'mso_mdoc',
    namespace: 'org.iso.18013.5.1',
    standardClaims: [
      { path: 'family_name', desc: 'Nachname des Inhabers' },
      { path: 'given_name', desc: 'Vorname(n) des Inhabers' },
      { path: 'birth_date', desc: 'Geburtsdatum' },
      { path: 'issue_date', desc: 'Erteilungsdatum des Fuehrerscheins' },
      { path: 'expiry_date', desc: 'Ablaufdatum des Fuehrerscheins' },
      { path: 'issuing_country', desc: 'Ausstellungsland' },
      { path: 'issuing_authority', desc: 'Ausstellende Fahrerlaubnisbehoerde' },
      { path: 'document_number', desc: 'Fuehrerscheinnummer' },
      { path: 'driving_privileges', desc: 'Erlaubte Fahrzeugklassen (Array z. B. B, AM, A)' },
      { path: 'portrait', desc: 'Passbild / Lichtbilddaten' },
      { path: 'unregistered_organ_donor', desc: 'Organspende-Hinweis' },
      { path: 'administrative_number', desc: 'Behoerdliche Referenznummer' },
      { path: 'sex', desc: 'Geschlecht' },
      { path: 'height', desc: 'Koerpergroesse' },
      { path: 'weight', desc: 'Gewicht' },
      { path: 'eye_colour', desc: 'Augenfarbe' },
      { path: 'hair_colour', desc: 'Haarfarbe' },
      { path: 'age_over_18', desc: 'Altersbestaetigung 18+ (Boolean)' },
      { path: 'age_over_21', desc: 'Altersbestaetigung 21+ (Boolean)' }
    ]
  }
};

class WrprcClaimParser {
  constructor() {
    this.report = { valid: true, errors: [], warnings: [], info: [] };
  }

  logError(msg) { this.report.valid = false; this.report.errors.push(msg); }
  logWarning(msg) { this.report.warnings.push(msg); }
  logInfo(msg) { this.report.info.push(msg); }

  createDemoJwt() {
    const header = { alg: 'ES256', typ: 'JWT' };
    const nowSec = Math.floor(Date.now() / 1000);
    const payload = {
      iss: 'https://registration.authority.example',
      sub: 'x509_hash:sample_client_id_hash',
      client_id: 'x509_hash:sample_client_id_hash',
      iat: nowSec - 3600,
      exp: nowSec + 31536000,
      jti: 'token_' + crypto.randomBytes(4).toString('hex'),
      verifier_info: {
        name: 'Muster-Dienstleister GmbH',
        sector: 'Financial Services',
        country: 'DE',
        allowed_credentials: [
          {
            id: 'pid_sdjwt',
            format: 'dc+sd-jwt',
            vct: 'urn:eudi:pid:de:1',
            allowed_claims: ['family_name', 'given_name', 'birth_date', 'age_over_18', 'address_data', 'nationalities']
          },
          {
            id: 'mdl_mdoc',
            format: 'mso_mdoc',
            doctype_value: 'org.iso.18013.5.1.mDL',
            namespace: 'org.iso.18013.5.1',
            allowed_claims: ['family_name', 'given_name', 'driving_privileges', 'issue_date', 'expiry_date']
          }
        ]
      }
    };

    const b64H = Buffer.from(JSON.stringify(header)).toString('base64url');
    const b64P = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const demoSig = crypto.randomBytes(64).toString('base64url');

    return b64H + '.' + b64P + '.' + demoSig;
  }

  parseInput(inputStr) {
    console.log('=================================================================');
    console.log('   EUDI WALLET - WRPRC CREDENTIALS & CLAIMS PARSER.              ');
    console.log('=================================================================');

    let jwtString = null;
    let sourceInfo = '';

    if (!inputStr) {
      const candidates = [
        'certs/registration_certificate.jwt',
        'registration_certificate.jwt'
      ];
      for (const cand of candidates) {
        const absP = path.resolve(process.cwd(), cand);
        if (fs.existsSync(absP)) {
          jwtString = fs.readFileSync(absP, 'utf8').trim();
          sourceInfo = 'Datei: ' + absP;
          break;
        }
      }

      if (!jwtString) {
        this.logInfo('No WRPRC file found in ./certs/');
        this.logInfo('Generating synthetic demo WRPRC instead...');
        jwtString = this.createDemoJwt();
        sourceInfo = 'Synthetic demo WRPRC';
      }
    } else {
      inputStr = inputStr.trim();
      if (fs.existsSync(inputStr)) {
        jwtString = fs.readFileSync(inputStr, 'utf8').trim();
        sourceInfo = 'Datei: ' + path.resolve(process.cwd(), inputStr);
      } else if (inputStr.split('.').length === 3) {
        jwtString = inputStr;
        sourceInfo = 'Direct JWT string';
      } else {
        this.logError('Input is not a valid file path nor a valid JWT string');
        return this.printReport();
      }
    }

    console.log('Inpout source: ' + sourceInfo);

    const parts = jwtString.split('.');
    if (parts.length !== 3) {
      this.logError('Invalid JWT format');
      return this.printReport();
    }

    let header, payload;
    try {
      header = JSON.parse(decodeBase64Url(parts[0]));
      this.logInfo('JWS header decoded successfully');
    } catch (e) {
      this.logError('Error while decding the JWS header: ' + e.message);
      return this.printReport();
    }

    try {
      payload = JSON.parse(decodeBase64Url(parts[1]));
      this.logInfo('WRPRC payload decoded successfully');
    } catch (e) {
      this.logError('Error while decoding the WRPRC payload: ' + e.message);
      return this.printReport();
    }

    this.analyzeHeader(header);
    this.analyzePayloadMetadata(payload);
    this.analyzeAllowedCredentialsAndClaims(payload);

    return this.printReport(header, payload);
  }

  analyzeHeader(header) {
    console.log('-----------------------------------------------------------------');
    console.log(' 1. HEADER META DATA (JWS JOSE HEADER)');
    console.log('-----------------------------------------------------------------');
    console.log('  - Algorithm (alg)    : ' + (header.alg || 'n/a'));
    console.log('  - Token Type (typ)   : ' + (header.typ || 'n/a'));

    if (header.x5c && Array.isArray(header.x5c)) {
      console.log('  - Cert chain         : ' + header.x5c.length + ' cert(s) in x5c header');
    } else {
      this.logWarning('No x5c header found in JWS');
    }
  }

  analyzePayloadMetadata(payload) {
    console.log('-----------------------------------------------------------------');
    console.log(' 2. WRPRC CERT & VERIFIER DATA');
    console.log('-----------------------------------------------------------------');

    const iss = payload.iss || 'n/a';
    const sub = payload.sub || payload.client_id || payload.rp_client_id || 'n/a';
    const jti = payload.jti || 'n/a';

    console.log('  - Issuer (iss)            : ' + iss);
    console.log('  - Client ID / Sub (sub)   : ' + sub);
    console.log('  - Token ID (jti)          : ' + jti);

    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.iat) {
      console.log('  - Issues at (iat)         : ' + new Date(payload.iat * 1000).toISOString());
    }
    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000).toISOString();
      const daysLeft = Math.floor((payload.exp - nowSec) / 86400);
      console.log('  - Valid until (exp)       : ' + expDate + ' (Remaining: ' + daysLeft + ' days)');

      if (nowSec > payload.exp) {
        this.logError('WRPRC is EXPIRED');
      } else {
        this.logInfo('Status: WRPRC is VALID');
      }
    }

    const vInfo = payload.verifier_info || payload.registration_metadata || {};
    if (vInfo.name || vInfo.organization_name) {
      console.log('  - Verifier Name           : ' + (vInfo.name || vInfo.organization_name));
    }
    if (vInfo.sector) {
      console.log('  - Sector                  : ' + vInfo.sector);
    }
    if (vInfo.country) {
      console.log('  - Registering Country     : ' + vInfo.country);
    }
  }

  analyzeAllowedCredentialsAndClaims(payload) {
    console.log('-----------------------------------------------------------------');
    console.log(' 3. CREDENTIALS & QUERIABLE ATTRIBUTES (CLAIMS)');
    console.log('-----------------------------------------------------------------');

    let rawCredentials = [];

    if (payload.verifier_info && Array.isArray(payload.verifier_info.allowed_credentials)) {
      rawCredentials = payload.verifier_info.allowed_credentials;
    } else if (Array.isArray(payload.allowed_credentials)) {
      rawCredentials = payload.allowed_credentials;
    } else if (Array.isArray(payload.credentials)) {
      rawCredentials = payload.credentials;
    } else if (payload.verifier_info && Array.isArray(payload.verifier_info.credentials)) {
      rawCredentials = payload.verifier_info.credentials;
    } else if (payload.authorized_claims) {
      rawCredentials = [payload.authorized_claims];
    }

    if (rawCredentials.length === 0) {
      this.logWarning('No allowed_credentials structure found in payload');
      console.log('  ⚠️  Cert does not contain attribute limitations -> full access');
      return;
    }

    console.log('Count of authorized credential types: ' + rawCredentials.length);

    rawCredentials.forEach((credItem, idx) => {
      let credId = 'Credential #' + (idx + 1);
      let format = 'Unknown';
      let doctypeOrVct = 'n/a';
      let allowedClaimsList = [];

      if (typeof credItem === 'string') {
        doctypeOrVct = credItem;
        if (credItem.includes('mDL') || credItem.includes('18013')) format = 'mso_mdoc';
        else format = 'dc+sd-jwt';
      } else if (typeof credItem === 'object') {
        credId = credItem.id || credId;
        format = credItem.format || credItem.type || format;
        doctypeOrVct = credItem.vct || credItem.doctype_value || credItem.doc_type || credItem.credential_type || 'n/a';

        allowedClaimsList = credItem.allowed_claims || credItem.claims || credItem.requested_attributes || credItem.paths || [];
      }

      const schemaLookup = STANDARD_CREDENTIAL_SCHEMAS[doctypeOrVct];
      const credName = schemaLookup ? schemaLookup.name : doctypeOrVct;

      console.log('📌 [' + (idx + 1) + '] CREDENTIAL: ' + credName);
      console.log('    - Credential ID    : ' + credId);
      console.log('    - Format           : ' + format);
      console.log('    - Doctype / VCT    : ' + doctypeOrVct);

      if (schemaLookup) {
        console.log('    - Namespace        : ' + schemaLookup.namespace);
      }

      console.log('    - Queriable Attributes (Claims):');

      if (allowedClaimsList.length > 0) {
        allowedClaimsList.forEach(claim => {
          let claimPathStr = '';
          if (typeof claim === 'string') {
            claimPathStr = claim;
          } else if (Array.isArray(claim)) {
            claimPathStr = claim.join(' -> ');
          } else if (typeof claim === 'object' && claim.path) {
            claimPathStr = Array.isArray(claim.path) ? claim.path.join(' -> ') : claim.path;
          }

          let desc = '';
          if (schemaLookup) {
            const matchedObj = schemaLookup.standardClaims.find(sc => sc.path === claimPathStr || claimPathStr.endsWith(sc.path));
            if (matchedObj) desc = ' (' + matchedObj.desc + ')';
          }

          console.log('       ✓  "' + claimPathStr + '"' + desc);
        });
      } else if (schemaLookup) {
        console.log('       ℹ️  all standards attributes of this credential are unlocked:');
        schemaLookup.standardClaims.forEach(sc => {
          console.log('       ✓  "' + sc.path + '" (' + sc.desc + ')');
        });
      } else {
        console.log('       ⚠️  no attributes filtered -> generic access');
      }

      console.log('');
    });
  }

  printReport(header, payload) {
    console.log('=================================================================');
    console.log('                     RESULTS                                     ');
    console.log('=================================================================');

    if (this.report.info.length > 0) {
      console.log('[INFO]:');
      this.report.info.forEach(msg => console.log('  ✓ ' + msg));
    }

    if (this.report.warnings.length > 0) {
      console.log('[WARNINGS]:');
      this.report.warnings.forEach(msg => console.log('  ⚠️  ' + msg));
    }

    if (this.report.errors.length > 0) {
      console.log('[ERRORS]:');
      this.report.errors.forEach(msg => console.log('  ❌ ' + msg));
    }

    console.log('-----------------------------------------------------------------');
    if (this.report.valid) {
      console.log('STATUS: ✅ VALID WRPRC');
    } else {
      console.log('STATUS: ❌ INVALID WRPRC');
    }
    console.log('-----------------------------------------------------------------');

    return this.report;
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const parser = new WrprcClaimParser();
  parser.parseInput(args[0]);
}

module.exports = WrprcClaimParser;
