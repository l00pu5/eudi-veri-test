# EUDI Wallet - Relying Party (RP) & Credential Issuer Sandbox

This is a testing / sandbox reference framework for testing **Credential Issuance (OpenID4VCI)** as well as **Credential Presentation (OPen4ID4VP)** within the **EUDI Wallet Ecosystem**.
This repository aims to provide a full local **EUDI Wallet Sandbox**. It provides the following components:
- a Node.js backend that provided the necessary API endpoints for credential issuance, credential presentation and status polling
- an interactive web UI for visualization purposes
- a simulator / test script that can invoke and validate the data flow(s)

---

## 📦 Project components

The project consists of the following modules and components:

1. **`eudi-verifier-helper_demo.js` (presentation verification):**
  * Verifies incoming presentations (SD-JWT VC or binary mdoc documents) in a tamper-proof fashion and provides a detailed integrity and hash matching log (`integrityLog`).
  * Is based solely on the  **native Node.js `crypto` module** (no additional npm dependencies).
  * Contains a mock **Erika Mustermann identity payload** for local validation simulation.

2. **`eudi-issuer-verifier.js` (issuance engine & PID provider):**
   * Simuliert die kryptografische Kernlogik eines **PID-Providers (Credential Issuers)** gemäß **OpenID4VCI 1.0** und dem **High-Assurance Interoperability Profile (HAIP)**.
   * Prüft eingehende Ausstellungsanfragen am **Token- und Credential-Endpoint**: Validiert die *Wallet Instance Attestation (WIA)* (Säule 4), den Schlüsselbesitznachweis des Nutzers (*Proof of Possession - PoP*) über die `c_nonce` sowie das *DPoP-Sender-Constrainting*.
   * Generiert und signiert eine echte **SD-JWT-basierte PID für Erika Mustermann** inklusive Zufalls-Salts für Selective Disclosure.

3. **`eudi-verifier-server_demo_.js` (REST API server):**
   * **Die EUDI-Ecosystem-Zentrale:** Vereint die Rollen des *Verifiziers (Relying Party)* und des *Herausgebers (PID Issuers)* auf einem Server (Port `3000`).
   * Exportiert beim Start automatisch seine flüchtigen Signaturschlüssel für den simulierten Trust-Store nach `demo-keys.json`, damit Test-Simulatoren WIA-Signaturen kryptografisch korrekt erzeugen können.
   * Speichert das verifizierte Dokumentenformat (`SD-JWT VC` oder `ISO mdoc`) sowie das kryptografische `integrityLog` und `rawSdList` in der Sitzung und liefert diese am Status-Endpoint aus.
   * **Präsentations-Endpoints:** Initialisierung (`GET /api/presentation/initiate`), JAR-Ausgabe (`GET /api/presentation/request-jwt`), Callback (`POST /api/presentation/callback`) via `direct_post.jwt` sowie Status-Polling (`GET /api/presentation/status`).
   * **Ausstellungs-Endpoints:** Initialisierung (`GET /api/issuance/initiate`), Issuer-Metadaten (`GET /api/issuance/.well-known/openid-credential-issuer`), Nonce-Endpoint (`POST /api/issuance/nonce`), Token-Endpoint (`POST /api/issuance/token`) und Credential-Endpoint (`POST /api/issuance/credential`).

4. **`index.html` (interactive web UI / frontend):**
   * Visualisiert das sichere Onboarding einer Relying Party sowie den Verschlüsselungs- und Transportstatus.
   * Unterscheidet **visuell dynamisch** zwischen PID (blau) und mDL (rosa) und enthält das interaktive **Kryptografischer Audit-Pfad (Entwickler-Analyse)** Widget, welches den genauen SHA-256 Hash-Abgleich der Disclosures und das mdoc `SessionTranscript` visualisiert.
   * **Bequeme Session-Kopplung:** Zeigt die aktive Onboarding Session-ID direkt unter dem QR-Code an und ermöglicht das Kopieren in die Zwischenablage mit einem einzigen Klick (Copy-to-Clipboard-Button), um das Einfügen in den Terminal-Simulator zu vereinfachen.
   * Rendert den dynamischen `openid4vp://`-QR-Code und führt ein asynchrones Status-Polling (AJAX) durch.
   * Präsentiert Erika Mustermanns verifiziertes Identitätsprofil nach erfolgreicher Übertragung und hebt hervor, ob die Belege im Klartext (`direct_post`) oder verschlüsselt (`direct_post.jwt` via JWE) empfangen wurden.

5. **`eudi-test-harness_demo_.js` (test simulator & end-to-end client):**
   * Der plattformunabhängige, einheitliche Krypto-Test-Simulator. Er simuliert das Verhalten einer eIDAS-konformen Wallet-App mathematisch korrekt am Terminal.
   * Er beherrscht vier Betriebsmodi (`--mode=1`, `--mode=2`, `--mode=3`, `--mode=4`) für einfache unverschlüsselte Onboardings, vollwertige ECDH-ES-verschlüsselte JWE-Präsentationen, den kompletten E2E-Lebenszyklus oder die Simulation von **mDL-Führerschein-Präsentationen** im binären CBOR-Format.
   * Schreibt am Ende jedes Laufs eine detaillierte **Laufzeit-Statistiktabelle** über die Krypto- und Übertragungszeiten in das Terminal.

---

## 🔄 Technische Datenflüsse in der Sandbox

### 1. Der Ausstellungs-Datenfluss (OpenID4VCI)
1. **Initiierung:** Die Wallet scannt ein *Credential Offer* (`openid-credential-offer://`), das vom Server bereitgestellt wird.
2. **Metadaten-Verbindung:** Die Wallet ruft die vom Server signierten Metadaten ab, um die unterstützten Ausweistypen und Krypto-Algorithmen zu prüfen.
3. **Nonce-Anforderung:** Die Wallet holt sich eine flüchtige Einmal-Nummer (`c_nonce` / `dpop_nonce`) vom Server.
4. **Token-Request:** Die Wallet beantragt ein Access Token am Token-Endpoint. Der Server validiert dabei die **WIA** des Wallet-Herausgebers und erzwingt **DPoP** (Binding des Tokens an den Wallet-Schlüssel).
5. **Ausweis-Herausgabe:** Am Credential-Endpoint verifiziert der Server den unlösbaren **Schlüsselbesitznachweis (PoP)** des Nutzers über die `c_nonce`. Bei Erfolg signiert die Ausstellungs-Engine des PID-Providers eine frische, mit Salts geschützte SD-JWT-PID und liefert sie an das Gerät aus.


### 3. Dynamische Beleg-Ausstellung: PID (SD-JWT) & mDL (ISO mdoc) (OpenID4VCI)
Mit der Version **v17** des Express-Servers und **v8** des Web-Frontends ist es nun möglich, sowohl staatliche **Personalausweise (PID / SD-JWT VC)** als auch **mobile Führerscheine (mDL / ISO mdoc)** mit **benutzerdefinierten Attributen** und einer **definierten Gültigkeitsdauer** direkt über das Web-Interface zu generieren und per QR-Code an Ihr Smartphone auszuliefern:

1. **Format-Auswahl & Claims-Konfiguration:** Auf der Weboberfläche im Tab "Ausstellung (Issuer)" wählen Sie über ein Dropdown das gewünschte Format (PID oder mDL). Die Formularfelder passen sich vollautomatisch an. Sie können Vorname, Nachname, Geburtsdatum, Nationalität, Anschrift, Führerscheinklassen (z.B. "B", "A") und die Gültigkeit in Tagen frei anpassen.
2. **Kopplung & Sitzungsspeicherung:** Wenn Sie auf "Angebot erzeugen" klicken, sendet das Frontend ein `POST /api/issuance/initiate` mitsamt dem gewählten Format und den Claims an den Server. Dieser erzeugt eine Ausstellungs-Sitzung, speichert die angepassten Daten im RAM und liefert den QR-Code mit der standardisierten `openid-credential-offer://` URI zurück (die passende Konfiguration wird in `.well-known/openid-credential-issuer` bereitgestellt).
3. **Kryptografische Bindung & CBOR-Codierung:** Holt die Wallet das mdoc-Zertifikat ab, klinkt sich der Token-Endpoint in diese spezifische Sitzung ein. Falls mDL gewählt ist, codiert der Server die Daten im RAM mittels eines lightweight CBOR-Encoders in eine standardkonforme, binäre `DeviceResponse`-Struktur und liefert sie als JWE-Umschlag zurück. Bei PID wird wie gewohnt ein signierter SD-JWT-Beleg erstellt.
4. **Erfolgs-Indikator:** Sobald die Wallet die Ausstellung abgeschlossen hat, schaltet das Web-Frontend dank bidirektionalem Polling sofort auf die Erfolgsmeldung um.

##### ⚙️ API-Schnittstelle: Initiierung der dynamischen Ausstellung (Server-Side)
Hier ist das im v17-Server implementierte Code-Segment, welches sowohl statische `GET`-Anfragen als auch dynamische `POST`-Requests für personalisierte Ausweise verarbeitet:

```javascript
app.all('/api/issuance/initiate', (req, res) => {
    const sessionId = 'session_iss_' + crypto.randomBytes(12).toString('hex');
    const wiaChallenge = 'challenge_iss_' + crypto.randomBytes(16).toString('hex');
    
    let customClaims = null;
    let customValidityDays = 90;
    let format = 'dc+sd-jwt';

    if (req.method === 'POST') {
        const { claims, validityDays, format: reqFormat } = req.body;
        if (claims) {
            customClaims = claims;
        }
        if (validityDays) {
            customValidityDays = parseInt(validityDays, 10) || 90;
        }
        if (reqFormat) {
            format = reqFormat;
        }
    }

    transactionStore.set(sessionId, {
        type: 'ISSUANCE',
        wiaChallenge: wiaChallenge,
        status: 'PENDING',
        claims: customClaims,
        validityDays: customValidityDays,
        format: format
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

    console.log(`[Issuer Server] Issuance Session initiiert. ID: ${sessionId}, Validity: ${customValidityDays} days`);

    res.json({
        success: true,
        sessionId: sessionId,
        wiaChallenge: wiaChallenge,
        credentialOfferUrl: offerUrl,
        qrCodeUrl: qrCodeUrl
    });
});
```


### 2. Der Präsentations-Datenfluss (OpenID4VP)
1. **QR-Scan:** Der Nutzer initiiert das Onboarding im Browser. Ein QR-Code mit der `request_uri` wird angezeigt.
2. **JAR-Sicherung (RFC 9101):** Die Wallet ruft die Anfrage ab. Der Server liefert ein signiertes **Request Object** aus, das die genaue **DCQL-Abfrage** (z. B. Altersprüfung over-18) enthält.
3. **Holder-Binding & direct_post:** Der Nutzer gibt die Attribute frei. Die Wallet erzeugt ein temporäres **Key Binding JWT**, signiert es mit dem hardware-geschützten privaten Schlüssel des Geräts unter Einbeziehung der Transaktions-Nonce und sendet das `vp_token` per HTTP-POST an die Callback-Schnittstelle.
4. **Validierung & Redirect:** Der Server prüft die 4 Säulen und sendet einen transienten `response_code` zurück, um den Browser des Nutzers sicher zur Onboarding-Erfolgsseite umzuleiten.

### 3. Anwendungsschicht-Verschlüsselung (direct_post.jwt - JWE)
1. **Verteilung der Verschlüsselungsschlüssel:** Bei der Initialisierung (`GET /api/presentation/initiate`) generiert der Server für jede Transaktion ein flüchtiges elliptisches P-256-Schlüsselpaar. Der öffentliche Schlüssel wird im JAR-Request als Teil der `client_metadata.jwks` deklariert.
2. **Kryptografische Absicherung (JWE):** Die Wallet führt ein ECDH-Key-Agreement durch, leitet mittels Concat KDF (RFC 7518) einen AES-Schlüssel ab und verschlüsselt das `vp_token` im JWE-Kompaktformat (AES-GCM).
3. **Entschlüsselung und Validierung:** Der Callback-Endpoint nimmt das JWE-Token entgegen, ermittelt die zugehörige Sitzung, führt die ECDH-Gegenrechnung durch und entschlüsselt die Identitätsdaten im geschützten RAM, bevor die 4-Säulen-Prüfung gestartet wird.

---


#### 📱 WICHTIG: Tests mit echten Smartphone-Wallets (z. B. via ngrok)
Wenn Sie QR-Codes mit einem echten Smartphone abscannen (unter Verwendung eines HTTPS-Tunnels wie `ngrok`), verlangt die Wallet-App gemäß dem eIDAS-Profil zwingend ein **X.509-Zertifikat im Header des JAR-Request-Objects (JWS)**, da die Client-ID als `x509_san_dns:client.example.org` deklariert ist.
Ohne dieses Zertifikat bricht das Smartphone mit dem Fehler `Invalid DCQL query: Validation Error No certificate in header` ab.

In **v15** wurde dieses Problem vollständig gelöst:
1. Der Server generiert beim ersten Start automatisch einen privaten EC-Schlüssel (`/workspace/scratch/rp-private-key.pem`) und ein passendes, selbstsigniertes X.509-Entwicklerzertifikat (`/workspace/scratch/rp-cert.pem`), welches den dNSName `client.example.org` als zwingend erforderliche **Subject Alternative Name (SAN)** Erweiterung deklariert.
2. Beim Abruf des JARs (`/api/presentation/request-jwt`) packt der Server dieses X.509-Zertifikat automatisch in das **`x5c`-Array des JWS-Headers**.

3. Damit verifiziert die Smartphone-Wallet-App die Domain `client.example.org` erfolgreich gegen das Zertifikat und lässt den verschlüsselten Datenabruf fehlerfrei durchlaufen!

##### 🛠️ Code-Snippet: Dynamische Zertifikats-Generierung & JWS-Einbindung (Node.js)

Hier ist das im Server (`eudi-verifier-server-v17.js`) integrierte Code-Segment, welches das Zertifikat und die SAN-Erweiterungen erzeugt und in die `x5c`-Header injiziert:

```javascript
// 1. Erzeugung des X.509 Zertifikats mit prime256v1 und SAN-dNSName
if (!fs.existsSync('/workspace/scratch/rp-private-key.pem')) {
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
    
    fs.writeFileSync('/workspace/scratch/openssl.cnf', cnfContent);
    execSync("openssl ecparam -name prime256v1 -genkey -noout -out /workspace/scratch/rp-private-key.pem");
    execSync("openssl req -new -x509 -key /workspace/scratch/rp-private-key.pem -out /workspace/scratch/rp-cert.pem -days 365 -config /workspace/scratch/openssl.cnf");
}

// 2. Extraktion des Base64-Zertifikatsdatenstroms für den x5c-Header
const certPem = fs.readFileSync('/workspace/scratch/rp-cert.pem', 'utf8');
const rpSigningCertBase64 = certPem
    .replace(/-----\s*(BEGIN|END)\s+CERTIFICATE\s*-----/g, '')
    .replace(/[\r\n]/g, '');

// 3. Einbindung in den JWS-Header des JARs
const jwtHeader = {
    alg: 'ES256',
    typ: 'oauth-authz-req+jwt',
    x5c: [ rpSigningCertBase64 ] // Übermittlung an die Wallet-App
};
```

##### 🔒 Vertrauensstellung (Trust) in der Wallet-App herstellen
Damit die Wallet-App auf Ihrem Smartphone das selbstsignierte Entwicklerzertifikat der Sandbox akzeptiert und nicht wegen einer unbekannten Zertifizierungsstelle abweist, gibt es zwei Wege:
1. **Entwickler-Zertifikat importieren:** Laden Sie die generierte Datei `rp-cert.pem` auf Ihr Smartphone und installieren Sie sie in den Systemeinstellungen unter *Sicherheit > Verschlüsselung & Vorrechte > CA-Zertifikat* als vertrauenswürdig.
2. **Entwickler-Modus (Sandbox-Bypass):** In den meisten EUDI-Wallet-Entwicklerversionen kann die Signaturketten-Prüfung für Testzwecke deaktiviert werden oder das Zertifikat der Relying Party wird in der lokalen App-Konfiguration direkt als vertrauenswürdig (Trust-List) hinterlegt.


## 🛠️ Installationsanleitung

### Voraussetzungen
* **Node.js** (Version 18.x oder höher empfohlen)

### 1. Abhängigkeiten installieren
Klonen Sie das Projekt und installieren Sie die für den Server- und Demobetrieb benötigten NPM-Hilfspakete:
```bash
npm install express express-session body-parser cors
```

---

--------------------------------------------------------------------------------


--------------------------------------------------------------------------------

#### 🌐 WICHTIG: Weboberfläche über localhost aufrufen (CORS-Schutz)
Öffnen Sie die `index.html` **nicht** per Doppelklick direkt aus dem Dateisystem (`file:///...`). Moderne Webbrowser blockieren asynchrone API-Abfragen (wie `fetch` zur Statusprüfung) aus dem lokalen Dateisystem aus Sicherheitsgründen (CORS-Policy).

Dank des in **v14** integrierten statischen Dateiservers müssen Sie stattdessen:
1. Den Server starten: `node eudi-verifier-server-v17.js`
2. Die Weboberfläche direkt im Browser über **`http://localhost:3000`** oder **`http://localhost:3000/index.html`** aufrufen.

Damit läuft die gesamte Kommunikation auf demselben Origin-Port, und CORS-Fehler im Browser werden vollständig vermieden!

#### 💡 Sitzungskopplung zwischen Browser (index.html) und Simulator
Wenn Sie die Ergebnisse direkt auf der Weboberfläche in Ihrem Webbrowser betrachten möchten, müssen Sie sicherstellen, dass das Testskript nicht seine eigene Sitzung erzeugt, sondern die **Sitzung des Browsers** bedient.

1. Klicken Sie in der Weboberfläche (`index.html`) auf **"Authentisierung starten"**.
2. Unter dem angezeigten QR-Code wird die rohe `openid4vp://`-URL im Klartext sowie die Sitzungs-ID ausgegeben (z. B. `session_8f3d...`).
3. Starten Sie das Testskript nun unter Übergabe dieses Sitzungsparameters (entweder `--sid` für die ID oder `--url` für den kompletten Link). Der Simulator führt dann die Krypto-Herausgabe für Erika Mustermann durch, sendet den verschlüsselten Callback jedoch an die offene Sitzung Ihres Browsers. Das Frontend schaltet daraufhin sofort auf die Erfolgs-Anzeige um!

Beispielaufruf:
```bash
# Über die Sitzungs-ID (empfohlen, sehr kurz)
node eudi-test-harness-v8.js --mode=3 --sid="SITZUNGS_ID_AUS_DEM_BROWSER"

# Oder über die vollständige QR-Code URL
node eudi-test-harness-v8.js --mode=3 --url="openid4vp://..."
```

## 🚀 Inbetriebnahme und E2E-Demonstration

Führen Sie die folgenden Schritte in separaten Terminal-Fenstern aus, um die EUDI-Integrations-Pipeline lokal live zu demonstrieren:

### Schritt 1: Den integrierten Sandbox-Server starten
Starten Sie das Express-Backend (Port `3000`). Der Server erzeugt beim Start automatisch ephemere Demotrust-Schlüssel und sichert diese nach `/workspace/scratch/demo-keys.json` ab:
```bash
node eudi-verifier-server-v17.js
```
*Ausgabe:* Der Server läuft unter `http://localhost:3000` und wartet auf Verbindungen.

### Schritt 2: Den neuen einheitlichen Test-Harness-Simulator starten
Führen Sie den integrierten Simulator im gewünschten Modus aus:

#### Option A: Der vollständige eIDAS-Datenfluss für PID (Dynamische SD-JWT Ausstellung + Präsentation)
Dies simuliert die komplette Kette für Personenidentifikationsdaten (PID):
1. Das Wallet bezieht einen frisch signierten, an einen lokalen Hardware-Device-Key gebundenen Ausweis vom Issuer (`/api/issuance`).
2. Das Wallet präsentiert diesen echten, dynamisch generierten Ausweis JWE-verschlüsselt am asynchronen Rückkanal der Relying Party (`/api/presentation`).
```bash
node eudi-test-harness-v8.js --mode=3
```

#### Option A2: Der vollständige eIDAS-Datenfluss für mDL (Dynamische mdoc/CBOR Ausstellung + mdoc Präsentation)
Dies ist die **vollständige, standardisierte E2E-Kette für den Führerschein (mDL)**:
1. Das Wallet bezieht ein dynamisch generiertes mDoc-Zertifikat (CBOR-kodiert) mit Ihren konfigurierten Daten vom Issuer-Endpoint.
2. Das Wallet präsentiert diese mDL JWE-verschlüsselt und mdoc-SessionTranscript-gebunden am direct_post-Rückkanal.
```bash
node eudi-test-harness-v8.js --mode=5
```

#### Option B: Die mdoc / mDL Führerschein-Präsentation (CBOR/SessionTranscript-Simulation)
Dieser Modus demonstriert die Integration von **mobilen Führerscheinen (mDL / ISO 18013-5)** im eIDAS-Ökosystem:
1. Der Client generiert mithilfe des integrierten CBOR-Encoders ein mathematisch 100% korrektes `SessionTranscript` unter Einbindung der Server-Nonce.
2. Er verpackt Erikas Führerscheindaten (B-Klasse, ausgestellt am 20.08.2026) in ein binäres `DeviceResponse`-CBOR-Dokument, verschlüsselt es mit ECDH-ES und AES-GCM und sendet es per `direct_post.jwt` an den Server.
3. Der Server-Helper `v5` entschlüsselt die Daten im RAM, parst die CBOR-Struktur und extrahiert die Führerschein-Claims für das Audit-Log.
```bash
node eudi-test-harness-v8.js --mode=4
```

#### Option C: Reine verschlüsselte Präsentation (JWE via ECDH-ES)
Simuliert das Onboarding-Szenario, bei dem das Wallet bereits einen statischen Ausweis besitzt und diesen Ende-zu-Ende verschlüsselt an die Relying Party überträgt:
```bash\nnode eudi-test-harness-v8.js --mode=2\n```

#### Option D: Unverschlüsseltes Schnell-Onboarding
Simuliert eine einfache, unverschlüsselte Belegübertragung zur schnellen Funktionsprüfung der Schnittstellen:
```bash
node eudi-test-harness-v8.js --mode=1
```

*Ergebnis:* Der Server verifiziert alle kryptografischen Signaturen und Schlüsselbesitznachweise. Am Ende der Ausführung gibt das Skript eine wunderschöne **Laufzeit-Statistiktabelle** über alle kryptografischen Operationen und HTTP-Schnittstellenlaufzeiten direkt in Ihrem Terminal aus!

---

## 🔒 Kryptografische Sicherheits-Säulen im Überblick

### Die 4 Säulen der Präsentations-Verifizierung
* **Säule 1 (Issuer Authenticity & Integrity):** Validiert die digitale Signatur des PID-Providers und führt einen strengen, mathematischen Integritätscheck durch: Jedes übermittelte Disclosure wird gehasht (SHA-256) und muss im `_sd`-Array des vom Aussteller signierten Credentials enthalten sein.
* **Säule 2 (Device Binding):** Verifiziert das Key-Binding-JWT des Geräts gegen den im Credential verankerten öffentlichen Schlüssel des Inhabers (`cnf.jwk`). Erhält Replay- und Phishing-Schutz via Transaktions-`nonce` und `client_id` (bzw. Web-Origin).
* **Säule 3 (Revocation Status):** Ermöglicht die Bitlisten-Sperrabfrage via Token Status List (TSL) oder mdoc CRL.
* **Säule 4 (Wallet Integrity):** Verifiziert die Signatur der *Wallet Instance Attestation (WIA)* des registrierten Herstellers.

### Die Ausstellungs-Sicherheitsmechanismen (OpenID4VCI)
* **DPoP (Sender Constrainting):** Erzwingt die Bindung unverschlüsselter Access Token an die Wallet-App-Identität zur Verhinderung von Session-Abfang-Angriffen (RFC 9449).
* **Proof of Possession (PoP):** Überprüft, ob das anfordernde Gerät den privaten Schlüssel kontrolliert, an den der Ausweis gekoppelt werden soll, indem die vom AS generierte `c_nonce` geräteseitig signiert werden muss (`application/openid4vci-proof+jwt`).

---

## 🔍 Kryptografische Entwickler-Analyse & Audit-Pfad

Das aktualisierte Web-Frontend (`index-v8.html.txt`) enthält ein interaktives **Audit-Panel für Krypto-Analysen** (aufklappbar):

### 1. Für SD-JWT VC (Selective Disclosure)
* **Hash-Integritätsprüfung:** Zeigt jedes übertragene Attribut mit seinem rohen base64url-kodierten Disclosure-String, dem dekodierten JSON-Wert `[salt, claim, value]`, dem daraus berechneten SHA-256 Hash und dem Status der mathematischen Validierung gegen das vom staatlichen Herausgeber signierte `_sd`-Array.
* **Erkennbare Datenminimierung:** Das System berechnet automatisch, welche Hash-Werte im Originalausweis enthalten waren, aber vom Wallet **nicht offengelegt** wurden. Diese unenthüllten Hashes werden als "Minimiert (Versteckt)" im Panel aufgeführt. Dies macht die eIDAS-Datenhoheit für Entwickler visuell greifbar.

### 2. Für ISO mdoc (mDL)
* **SessionTranscript-Diagnostic:** Visualisiert die CBOR-Diagnostic-Struktur des `SessionTranscript`-Handshakes (Handover, Client-ID, Nonce und Ephemerals). Dies verdeutlicht, wie Belege kryptografisch an den aktuellen Transport-Sitzungskanal gebunden werden, um Replay-Angriffe vollständig zu unterbinden.

---

## 📄 Lizenz
Dieses Projekt ist lizenziert unter der Creative Commons Attribution 4.0 International (CC BY 4.0).
