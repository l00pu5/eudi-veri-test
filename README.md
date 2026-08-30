# EUDI Wallet - Relying Party (RP) & Credential Issuer Sandbox

This is a testing / sandbox reference framework for testing **Credential Issuance (OpenID4VCI)** as well as **Credential Presentation (OPen4ID4VP)** within the **EUDI Wallet Ecosystem**.
This repository aims to provide a full local **EUDI Wallet Sandbox**. It provides the following components:
- a Node.js backend that provided the necessary API endpoints for credential issuance, credential presentation and status polling
- an interactive web UI for visualization purposes
- a simulator / test script that can invoke and validate the data flow(s)

---

## 📦 Project components

The project consists of the following modules and components:

1. **`eudi-verifier-helper_demo.js` (presentation verification)**
  * Verifies incoming presentations (SD-JWT VC or binary mdoc documents) in a tamper-proof fashion and provides a detailed integrity and hash matching log (`integrityLog`).
  * Is based solely on the  **native Node.js `crypto` module** (no additional npm dependencies).
  * Contains a mock **Erika Mustermann identity payload** for local validation simulation.

2. **`eudi-issuer-verifier.js` (issuance engine & PID provider)**
  * simulates cryptographic core logic of a **PID Provider (Crednential Issuer)** in accordance with **OpenID4VCI** and **HAIP (High-Assurance Interoperability Profile)**.
  * checks incoming issuance requests via the **credential and token endpoints** - validates the **Wallet Instance Attestation (WIA)**, the key **Proof of Possession (PoP)** of the user via `c_nonce` and enforces **DPoP Sender Constrainting**.
  * generates an actual **SD-JWT-based PID for Erika Mustermann** including randomized salting for selective disclosures.

3. **`eudi-verifier-server_demo_.js` (REST API server)**
  * provided **Verifier (Relying Party)** and **Issuer (PID Provider)** functionality
  * exports transient keys for simulating the trust store (`demo-keys.json`) to allow the simulation script to generate a cryptographically correct WIA signature
  * saves the verified document (`SD-JWT VC` or `ISO mdoc`) as well as the cryptographic `integrityLog` + `rawSdList` within the session and delivers them to the status endpoint
  * **Presentation Endpoint**:
    * Initialization (`GET /api/presentation/initiate`)
    * JAR generation (`GET /api/presentation/request-jwt`)
    * Callback (`POST /api/presentation/callback`) via `direct_post.jwt`
    * Status polling (`GET /api/presentation/status`)
  * **Issuance Endpoints**:
    * Initialization (`GET /api/issuance/initiate`)
    * Issuer metadata (`GET /api/issuance/.well-known/openid-credential-issuer`)
    * Nonce retrieval (`GET /api/issuance/nonce`)
    * Token exchange (`POST /api/issuance/token`)
    * Credential exchange (`POST /api/issuance/credential`)

4. **`index.html` (interactive web UI / frontend)**
  * vsualizes the RP onboarding + the encryption & credential transport status
  * distinguishes **visually** between PID (blue) and mDL (pink) and contains the **Audit Path Widget** which visualizes the hash verification and the mdoc `SessionTranscript`
  * **Session Coupling**: shows the session ID underneath the QR code, which allows for easy copy&pasting to faciliatte operating the simulator script more easily
  * renders a dynamic QR code that encodes the `opendid4vp://` request and conducts asynchronous status polling (AJAX)
  * presents the verified Eriks Mustermann mock ID profile and highlights whether the attributes have been transmitted as clear text (`drect_post`) or encrypted via JWE (`direct_post.jwt`)

5. **`eudi-test-harness_demo_.js` (test simulator & end-to-end client)**
  * crypto test simulator thar simulates the wallet app behavior
  * offers different operating modes (`--mode=[1-5]`) to simulate the following interaction types:
    * mode 1: unencrypted mock presentation (`direct_post`)
    * mode 2: encrypted mock presentation via JWE (`direct_post.jwt`)
    * mode 3: end-to-end test (issuance + JWE presentation)
    * mode 4: mdoc CBOR presentation
    * mode 5: end-to-end mdoc flow (issuance + CBOR presentation)
  * presents a statistics table after each test run for perforance tracking

---

## 🔄 Data flows within the sandbox

### 1. Issuance data flow (OpenID4VCI)
1. **Initiation**: wallet scans a *Credential Offer* (`openid-credential-offer://`) that is being provided by the server.
2. **Metadata Retrieval**: wallet will retrieve server-signe metadata to check the supported credential types crypto alogrithms.
3. **Nonce Request**: wallet obtains a transient one-time number (`c_nonce` / `dpop_nonce`) from the server.
4. **Token Request**: wallet requests the access token from the token endpoint. The server will validate the **WIA** of the wallet provider and enforces the **DPoP** (binding the token to the wallet key).
5. **PID Issuance**: server will verify the **PoP** at the credential endpoint via the `c_nonce`. If successful, the issuance engine of the PID provider will sign a salted SD-JWT PID and delivers it to the device.


### 3. Dynamic Credential Issuance: PID (SD-JWT) & mDL (ISO mdoc) (OpenID4VCI)
The web interface allows for the issuance of **PID (SD-JWT VC)** and **mDL (mdoc)** with **user-defined attributes** and a **custom validity period**. An issuance offer is exposed via QR code, which can be scanned directly with the smartphone.

Sequence:
1. **Format selection & claim configuration**: select the desired format (PID or mDL) -> the form field will dynamically adapt depending on the format selection. You may now alter first name, last name, date of birt, nationality, address, driver license clas and validity period accordingly.
2. **Coupling & session initiation**: once you initiate the credential offer, the frontend wlll post to `POST /api/issuance/initiate` and will pass the claim format and the claims to the server. This will initiate an issuance session and will generate the QR code that encodes the credential offer (`openid-credential-offer://` URI). The config is being made available via `.well-known/openid-credential-issuer`.
3. **Cryptographic binding & CBOR encoding**: as soon as the wallet fetches the mdoc certificate, the token endpoint will link to this specific session. If mDL is selected, the server will encode the data via CBOR to a binary `DeviceResponse` structure and delivers it within a JWE envelope (i.e. encrypted). In case of a PID, an SD-JWT credential will be created.
4. **Success indication**: as soon as the wallet has completed the issuance, the web frontend will take notice by ways of continuous status polling and will reflect the success status accordingly.

##### ⚙️ API Interface: initiation of the dynamic issuance

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

  console.log(`[Issuer Server] Issuance session initiated. ID: ${sessionId}, Validity: ${customValidityDays} days`);

  res.json({
    success: true,
    sessionId: sessionId,
    wiaChallenge: wiaChallenge,
    credentialOfferUrl: offerUrl,
    qrCodeUrl: qrCodeUrl
  });
});
```

### 2. Presentation Data Flow (OpenID4VP)
1. **QR scan**: user initiates the onboarding in the browser by scanning the QR code with the `request_uri`.
2. **JAR (RFC 9101)**: wallet fetches the request. The server will deliver a signed **Request Object** that contains the actual **DCQL query** for the respective attributes that the **Relying Party** wants to inspect.
3. **Holderb binding & direct_post**: user authorizes the trasaction. The wallet generates a temporary signed **Key Binding JWT** (signed using the hardware-protected private key of the device and the transaction nonce) and sends the `vp_token` via HTTP POST to the callback endpoint.
4. **Validation & redirect**: server validates the integrity of the wallet response and sends a transient `response_code` to the wallet to redirect the user agent (browser) to the onboarding success page.

### 3. Application layer encryption (direct_post.jwt -> JWE)
1. **Distribution of encryption keys**: upon initialization (`GET /api/presentation/initiate`) the server will generate a transiene elliptic P-256 key pair for each transaction. The public keys will be declared in the JAR request as part of `client_metadata.jwks`.
2. **Enforicjg cryptographic security (JWE)**: wallet will perform an ECDH key agreement, derives an AES key via Concat KDF (RFC 7518) amd encrypts the `vp_token` as a JWE (AES-GCM).
3. **Decryption and validation**: callback endpoint will receive the JWE token, determines the corresponding session, performs the ECDH counter-check and decrypts the identity data before performing the validity checks.

---

#### 📱 ATTENTION: tests using an actual smartphone wallet (e.g. via ngrok)
If a QR is being scanned using an actual wallet implementation on a smartphone (e.g by making the locally hosted server instance accessible using an HTTPS tunnel like `bgrok`), an **X.509 certificate** will be required by the app in the **JAR** object header. This is due to the fact that the client ID is declared as `x509_san_dns:client.example.org`.
If this certificate is not present, the session will be aborted and the smartphone wallet app will log an error to the effect of `Invalid DCQL query: Validation Error No certificate in header`.

How this behavior is currently tackled:
1. The server will automatically generate a private EC key (`./rp-private-key.pem`) and a matching self-signed X.509 developer certificate (`./rp-cert.pem`) which will declare the dNSName `client.example.org` as a mandatory **Subject Alternative Name (SAN)** extension.
2. Upon requesting the JAR (`/api/presentation/request-jwt`) the server will automatically add the certificate to the **`x5c` array of the JWS header**.
3. The smartphone wallet app can verify the domain `client.example.org` against this certificate.

##### 🛠️ Code snippet: dynamic certificate generation & linkage in JWS

This is the server's code segment that generates the certificate, the SAN extensions and injects it into the `x5c`header:

```javascript
// 1. Generating the X.509 certificate with prime256v1 and SAN dNSName
if (!fs.existsSync('./rp-private-key.pem')) {
  const cnfContent = `
    [req]
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
    
  fs.writeFileSync('./openssl.cnf', cnfContent);
  execSync("openssl ecparam -name prime256v1 -genkey -noout -out ./rp-private-key.pem");
  execSync("openssl req -new -x509 -key ./rp-private-key.pem -out ./rp-cert.pem -days 365 -config ./openssl.cnf");
}

// 2. Extracting the base64 data stream for the x5c header
const certPem = fs.readFileSync('./rp-cert.pem', 'utf8');
const rpSigningCertBase64 = certPem
  .replace(/-----\s*(BEGIN|END)\s+CERTIFICATE\s*-----/g, '')
  .replace(/[\r\n]/g, '');

// 3. Inclusion in the JAR's JWS header
const jwtHeader = {
  alg: 'ES256',
  typ: 'oauth-authz-req+jwt',
  x5c: [ rpSigningCertBase64 ] // transmitted to wallet app
};
```

##### 🔒 Establish trust in the wallet app
In order for the smartphone wallet app to accept the self-signed developer certificate of the sandbox and to avoid running into situations where the certificate is rejected because of an unknwon certificate authority, we would have the following options:
1. **Import developer certificate**: transfer the automatically generated file `rp-cert.pem` to your smartphone and install it using the system settings to declare it as trustworthy (*Security > Encryption > CA certificate*.
2. **Developer mode (sandbox by-pass)**: most wallet app developer releases allow disabling the signature chain verification for testing purposes. Alternatively, the RP certificate can be explicitly declared trustworthy in the app config options by adding it to the trust list.

## 🛠️ Install instructions

### Requirements
* **Node.js** (>=18.x)

### Installing dependencies
Clone the repo and install the depencies as follows (will pull dependencies from `package.json`):
```bash
npm install
```

---

#### 🌐 IMPORTANT: invoke web UI via localhost
Open `index.html` via `http://localhost:3000` or `http://localhost:3000/index.html`, otherwise the relative URL paths of the fetch requests will trigger CORS errors.

#### 💡 Session coupling between browser (index.html) and the simulator
If you would like to track the progress and view the results in the web UI, you'll need to ensure that the test script doesn't generate its own session, but instead uses the **existing session** of the browser.

1. In the web UI (`index.html`) click on **"Start Authentication"**.
2. The plain `openid4vp://` URL will be displayed below the QR code and the session ID will be mentioned (e.g. `session_8f3d...`).
3. Launch the test script and pass the session ID as a parameter (either via `--sid` by using the session ID or by using `--url` for passing the entire link from which the session ID will be filtered).

Invocation:
```bash
# via session ID (recommended)
node eudi-test-harness_demo.js --mode=3 --sid="SESSION_ID"

# via full URL
node eudi-test-harness_demo_.js --mode=3 --url="openid4vp://..."
```

## 🚀 Usage / end-to-end demonstration

Execute the following steps in separate terminal windows to demonstrate the pipeline locally:

### Step 1: launching the sandbox server
Launch the Express backend on port `3000`. The server will automatically generate the demo trust keys upon starting and will save them at `./demo-keys.json`:
```bash
node eudi-verifier-server_demo.js
```
*Output*: Server is running on `http://localhost:3000`, awaiting incoming connections.

### Step 2: launching the test harness / simulator script
Execute the simulator in the desired operation mode:

#### Option A: full eIDAS data flow for PID (dynmic SD-JWT issuance + presentation) [mode 3]
This will simulate the entire chain of events for PID data:
1. The wallet will obtain a signed PID from the issuer (`/api/issuance`) that is bound to a local hardware device key.
2. The wallet will present this PID via JWE to the asynchronous back channel of the RP (`/api/presentation`.
```bash
node eudi-test-harness_demo_.js --mode=3
```

#### Option A2: full eIDAS data flow for mDL (dynamic mdoc/CBOR issuance + mdoc presentation) [mode 5]
This will simulate the **end-to-end flow for the mDL issuance + presentation**:
1. The wallet will obtain a dynamically generated mDoc certificate (CBOR-encoded) with the configured data from the issuer endpoint.
2. The wallet will present the mDL JWE-encrypted and SessionTranscript-bound on the direct_post back channel.
```bash
node eudi-test-harness_demo_.js --mode=5
```

#### Option B: mdoc / MDL presentation (CBOR / SessionTranscript simulation) [mode 4]
This mode demonstrates the mDL integration:
1. The client generates a CBOR-encoded `SessionTranscript` while taking into consideration the server nonce.
2. The client will pack the mDL into a binary `DeviceResponse` CBOR document, will encrypt it (ECDH-ES + AES-GCM) and will send it via `direct_post.jwt` to the server.
3. The server will decrypt the data, parse the CBOR structure and extract the mDL claims for the audit log.
```bash
node eudi-test-harness_demo_.js --mode=4
```

#### Option C: encrypted presentation (JWE via ECDH-ES) [mode 2]
Simulates the onboarding scenario where the wallet is already in possession of a PID and is presenting it end-to-end encrypted to the RP:
```bash
node eudi-test-harness_demo_.js --mode=2
```

#### Option D: unencrypted quick onboarding [mode 1]
Simulates a simple unencrypted credential presentation. For testing purposes to see if the interfaces are interaction with each other accordingly:
```bash
node eudi-test-harness_demo_.js --mode=1
```

*Result*: the server will verifiy the cryptographic signatures and PoP(s). After execution, the script will provide a **runtime statistic** in the terminal.

---

## 🔒 Overview of cryptographic validation checks

### 4 pillars of presentation verification
* **Pillar 1 (Issuer Authenticity & Integrity)**: Validates the digital signature of the PID provider and performs a strict mathematical integrity check: every disclosure is going to be hashed (SHA-256) and needs to be present in the `_sd` array of the issues credential document.
* **Pillar 2 (Device Binding)**: Verifies the key binding JWT of the device against the public key that is anchored in the credentail (`cnf.jwk`). Maintains reply and phishing protection via transaction `nonce` and `client_id`.
* **Pillar 3 (Revocation Status)**: Facilitates the bit list revocatation status query via Token StatUs List (TSL) or mdoc CRL.
* **Pillar 4 (Wallet Integrity)**: Verifies the WIA signature of the wallet provider.

### Issuance security mechanisms (OpenID4VCI)
* **DPoP (Sender Constrainting)**: enforces binding of unencrypted access token to the wallet identity to prevent session capturing attacks (RFC 9449).
* **Proof of Possession (PoP)**: verifies whether the requesting device is in control of the provate key to which the credential shall be coupled by letting the issuer-provided `c_nonce` be signed by the dveice (`application/openid4vci-proof+jwt`).

---

## 🔍 Cryptographic analysis & audit path

The web UI (`index.html`) contains an interactive **Audit panel**:

### 1. for SD-JWT VC (Selective Disclosure)
* **Hash Integrity Check**: shows every attribute with its raw base64url-encoded disclosure string, the decoded JSON value `[salt, claim, value]`, the SHA-256 has value and the status of the validation against the official signed credential (`sd` array).
* **Data Minimization**: the system will calculate, which hash values have been part of the original signed credential, but haven't been **disclosed** by the wallet. These undisclosed claims will be be listed as "hidden" in the panel to visualize the disclosure status.

### 2. for ISO mdoc (mDL)
* **SessionTranscript diagnostic**: visualizes the CBOR structure of the `SessionTranscript` handshake (handover, client ID, nonce and ephemerals) to illustrate how credentials are cryptographically bound to the current transport session to prevent reply attack from being initiated.

---

## 📄 License
This project is licensed under the Creative Commons Attribution 4.0 International license (CC BY 4.0).
