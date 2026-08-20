# EUDI Wallet - Relying Party (RP) Sandbox & Test-Harness

Ein entwicklerfreundliches, herstellerneutrales Referenz-Framework zur Implementierung und Erprobung einer **Relying Party (RP) / Verifier** im nationalen **EUDI-Wallet-Ökosystem (eIDAS 2.0)**. 

Dieses Repository enthält ein vollständiges Node.js-Backend, ein interaktives HTML5-Demonstrations-Frontend sowie ein automatisiertes Bash-Test-Harness zur Simulation einer Wallet-Präsentation unter Verwendung von **OpenID for Verifiable Presentations (OpenID4VP)** und **IETF SD-JWT VC**.

---

## 📦 Komponenten des Projekts

Das Projekt besteht aus vier eng verzahnten, leicht verständlichen Modulen:

1. **`eudi-verifier-helper-v2.js` (Core-Bibliothek):**
   * Verifiziert empfangene Nachweise fälschungssicher entlang der gesetzlichen **4 Säulen der Verifizierung**.
   * Basiert ausschließlich auf dem **nativen Node.js `crypto`-Modul** (keine externen `npm`-Abhängigkeiten, ideal für Security-Audits).
   * Enthält eine voll funktionsfähige, lokale **Erika-Mustermann-Identitätssimulation** für asynchrone Selbsttests.

2. **`eudi-verifier-server.js` (Express REST-API):**
   * Verwaltet den Lebenszyklus transienter Sitzungen (Session-Handling mit CSRF- und Session-Fixation-Schutz).
   * Signiert und liefert **JWT-Secured Authorization Requests (JAR - RFC 9101)** aus, welche die **DCQL (Digital Credentials Query Language)** Abfrage enthalten.
   * Implementiert die offizielle **`direct_post` (HTTP-POST)** Schnittstelle für die asynchrone Datenannahme aus der Wallet.

3. **`index.html` (Tailwind CSS Web-Frontend):**
   * Bietet eine intuitive Benutzeroberfläche zur Demonstration des Logins mit der Wallet (Cross-Device-Szenario).
   * Generiert dynamisch den startbereiten `openid4vp://`-QR-Code und führt ein Echtzeit-Status-Polling (AJAX) durch.
   * Visualisiert Erika Mustermanns verifiziertes Identitätsprofil inklusive eines detaillierten Audit-Berichts.

4. **`eudi-test-harness.sh` (Bash-Testskript / Wallet-Simulator):**
   * Automatisiert den gesamten Präsentations- und Validierungsfluss auf Kommandozeilenebene.
   * Simuliert eine EUDI-Wallet-App: Ruft den verschlüsselten JAR-Request ab, erzeugt ein echtes SD-JWT VC mit Holder-Binding-Proof (Key Binding) und einer Wallet Instance Attestation (WIA) und sendet den HTTP-POST an die RP-Schnittstelle.

---

## 🛠️ Installationsanleitung

### Voraussetzungen
* **Node.js** (Version 18.x oder höher empfohlen)
* **bash** und **curl** (nur für die Test-Harness-Simulation)

### 1. Repository klonen & Abhängigkeiten installieren
Installieren Sie Express und die für den Demobetrieb des Servers benötigten Hilfspakete:
```bash
# Abhängigkeiten für den Web-Server installieren
npm install express express-session body-parser cors
```

---

## 🚀 Inbetriebnahme und Demonstration (Echtzeit-Durchlauf)

Führen Sie die folgenden Schritte in separaten Terminal-Fenstern aus, um die vollständige Integrations-Pipeline lokal zu demonstrieren:

### Schritt 1: Express REST-API Server starten
Starten Sie das Backend-Schnittstellenmodul. Der Server generiert beim Start automatisch ephemere Schlüsselpaare für den Demo-Betrieb (Trust-Store):
```bash
node eudi-verifier-server.js
```
*Ausgabe:* Der Server läuft lokal unter `http://localhost:3000` und wartet auf eingehende Verbindungen.

### Schritt 2: Frontend im Browser öffnen
Öffnen Sie die Datei `index.html` in einem beliebigen Webbrowser.
1. Klicken Sie auf **"Authentisierung starten"**.
2. Das System generiert eine eindeutige Transaktions-Nonce und zeigt den dynamischen **QR-Code** für die Wallet an.
3. Das Frontend wechselt in den Wartezustand und fragt im Hintergrund den Session-Status ab.

### Schritt 3: Simulation ausführen (Bash Test-Harness)
Starten Sie den Wallet-Simulator in einem neuen Terminal. Dieses Skript lädt das JAR-Dokument vom Server herunter, signiert die Präsentations-Claims für **Erika Mustermann** und führt den HTTPS-POST an das Callback-Interface aus:
```bash
chmod +x eudi-test-harness.sh
./eudi-test-harness.sh
```
*Was passiert im Hintergrund?*
* Das Skript liest die Transaktionsparameter aus dem QR-Code aus.
* Es berechnet die Hash-Werte für Erikas Disclosures (Vorname, Nachname, Geburtsdatum, Volljährigkeit, Meldeadresse Köln).
* Es erzeugt das **Key Binding JWT** und verknüpft es mit der Server-Nonce.
* Der Callback (`direct_post`) wird an das Express-Backend gesendet.

**Ergebnis:** 
* Im Terminal des Test-Harnesses sehen Sie die Erfolgsmeldung und das verifizierte JSON-Profil.
* Das Web-Frontend (`index.html`) schaltet **vollautomatisch in Millisekunden** auf den grünen Erfolgs-Zustand um und zeigt Erika Mustermanns digitalen Ausweis inklusive des Audit-Berichts an.

---

## 🔒 Die 4 Säulen der Verifizierung im Code

Die Verifizierung in `eudi-verifier-helper-v2.js` ist streng nach den europäischen Architekturvorgaben des eIDAS 2.0 Frameworks strukturiert:

1. **Säule 1: Aussteller-Authentizität (Issuer Authenticity):** Der Verifizierer prüft die kryptografische Signatur des SD-JWTs gegen die staatliche Trusted List. Er berechnet die SHA-256-Hashes der offengelegten Klartext-Disclosures und vergleicht diese mit den vom Aussteller signierten Hashing-Arrays.
2. **Säule 2: Gerätebindung (Device & Key Binding):** Verifiziert das *Key-Binding-JWT*, welches mit dem privaten Schlüssel in der sicheren Hardware (WSCD) des Nutzers signiert wurde. Es wird geprüft, ob die Nonce mit der Transaktions-Nonce übereinstimmt (Replay-Schutz) und ob die `client_id` der RP entspricht (Phishing-Schutz).
3. **Säule 3: Sperrstatus (Revocation Status):** Das Modul parst den `status`-Claim im Token Status List (TSL) Format und bereitet die Prüfung der Bit-Positionen zur Echtzeit-Sperrabfrage vor.
4. **Säule 4: Wallet-Authentizität (Wallet Validation):** Es verifiziert das *Wallet Instance Attestation (WIA)* JWT des Wallet-Herausgebers, um sicherzustellen, dass es sich um eine echte, unmodifizierte und zertifizierte Wallet-App handelt.

---

## 📄 Lizenz
Dieses Projekt ist lizenziert unter der Creative Commons Attribution 4.0 International (CC BY 4.0).
