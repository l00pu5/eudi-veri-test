# EUDI Wallet - Relying Party (RP) Test Harness & Integration Simulator (ERP-THIS)

A developer-friendly, vendor-neutral reference framework for implementing and testing a **Relying Party / Verifier (OpenID4VP)** as well as the **Issuance (OpenID4VCI)** aspect within the nation **EUDI Wallet Ecosystem** in accordance with **eIDAS2.0**.

This repository provides a local **EUDI Wallet Sandbox** with a Node.js backend that can simulate credential issuance as well as credential presentation and verification scenarios.

Furthermore, a test script `eudi-test-harness.js` is provided that will simulate end-to-end flows for the aforementioned scenarios.

---

## 📦 Project Components / Modules

The project consists the following related modules:

1. **`eudi-verifier-helper.js` (Core Library / Presentation Verifier):**
  * verifies incoming credentials in accordance with the **4 pillars of verification**
  * is based solely on **native Node.js `crypto` module** - no other external `npm` dependencies
  * contains a full-blown mockup **Erika Mustermann identity (payload) simulation** for testing purposes

2. **`eudi-issuer-verifier.js` (PID Provider & Issuance Engine)**
  * simulates cryptographic core logic of a **PID provider / credential issuer** in accordance with **OpenID4VCI 1.0** and **HAIP (High-Assurance Interoperability Profile)**
  * verifies and checks incoming issuance requests towards **token and credential endpoints**
  * validates WIA & PoP via `c_nonce` as well as *DPoP constrainting*
  * generates and signs **SD-JWT VC PID for Erika Mustermann** (mock identity) including randomized salts for selective disclosures

3. **`eudi-verifier-server.js` (Express-based REST API):**
  * provides **Verifier (RP)** and **Provider (PID Issuer)** functionality and the corresponding API endpoints
  * exports its transient signature keys for the simulated trust store to `demo-keys.json`, allowing test simulators to generate cryptographic WIA signatures
  * saves the `SD-JWT VC` or `ISO mdoc` documents in the active transaction session and delivers them to the status interface
  * provides **Presentation Endpoints** for initializing (`GET /api/presentation/initiate`), JAR generation (`GET /api/presetation/request-jwt`), callback (`POST /api/presentation/callback`) via `direct_post.jwr` and status polling (`GET /api/presentation/status`)
  * provides **Issuance Endpoints** for initializing & credental offer (`GET /api/issuance/initiate`), issuer metadata (`GET /api/issuance/.well-known/openid-credential-issuer`), nonce endpoint (`POST /api/issuance/nonce`), token endpoint (`POST /api/issuance/token`) and credential endpoint (`POST /api/issuance/credential`)

4. **`index.html` (Web Frontend):**
  * intuitive user interface for demonstrating the cross-device wallet interaction flow
  `visualizes RP onboarding and encryption & transport status
  * **visual distiction** between PID (blue) and mDL (pink) document processing
  * generates QR code with `openid4vp` request
  * conducts real-time polling of fulfilment status
  * visualizes mock identity profile / audit report
  * presents the processed identity disclosures and highlights whether the disclosures have been processed encrypted (`direct_post.jwt`) or unencrypted (`direct_post`))

5. **`eudi-test-harness.sh` (Bash Test Script / Wallet Simulation):**
  * automates the presentation and validation flow via command line
  * simulates EUDI wallet interaction: retrieves the JAR request, generates SD-JWT VC with holder binding proof + WIA and posts the data to the RP interface
  * end-to-end test cycle
  * 4 operating modes, depending on the test scenario that shall be executed
  * `mode=1`: unencrypted direct_post presentation
  * `mode=2`: encrypted direct_post JWE presentation
  * `mode=3`: SD-JWT VC issuance & presentation, end-to-end flow
  * `mode=4`: mDL issuance & presentation, end-to-end flow

6. **`eudi-jwe-test-client.js` (JWE flow simulation)**
  * simulates and end-to-end presentation flow using JWE instead of unencrypted data

---

## 🔄 Data flows within the sandbox

### 1. Issuance data flow (OpenID4VCI)
1. **Intitiation**: wallet will scan a *Credential Offer* (`openid-credential-offer://`) that is being made available on the server
2. **Linkage of metadata**: wallet will retrieve the signed metadata from the server, to check the supported credential types and cryptographic algorithms
3. **Nonce retrieval**: wallet will obtain a volatile one-time nonce (`c_nonce` / `dpop_nonce`) from the server
4. **Token request**: wallet will ask for an access token via the token endpoint. Server will validate the WIA and enforces **DPoP** (binding of the token to the wallet key)
5. **PID Issuance**: server will verify the wallet PoP via the `c_nonce` on the credential endpoint. Success will triger the issuance engine to provide a SD-JWT PID that has been salted randomly

### 2. Presentation data flow (OpenID4VP)
1. **QR coe**: onboarding is initiated by the user within the browser. A QR code that contains the `request_uri` is generated and being shown
2. **JAR Retrieval**: wallet retrieves the request. Server delivers a signed **Request Object** that contains the **DCQL Query** to the desired credential attributes
3. **Holder Bindung**: user provides consent to sharing the requested attributes as specified within the **DCQL Query**. Wallet generated a temporary **KEy Binding JWT**, signs it with the hardware-protected private key while taking into consideration the transaction nonce and sends the `vp_token` via **HTTP POST** to the callback interface
4. **Validation & Redirect**: server verifies the data and sends a transient `response_code` to redirect the user agent safely to the onboarding success page

### 3. Application layer encryption (direct_post.jwt - JWE)
1. **Distribution of encryption keys**: upon initiation (`GET /api/presentation/initiate`) the server will generate transient elliptic P-256 key pairs. The public key will be declared as part of `client_metadata.jwks` in the JAR request
2. **JWE**: wallet will encrypt the `vp_token` as JWE
3. **Decryption and validation**: callback endpoint accepts the JWE token, determines the corresponding session and decyphers the identity claims before initiating the 4 pillar validation

## 🛠️ Installation instructions

### Requirements
* **Node.js** (>=18.x)
* **bash** and **curl** (only require for the test harness Bash script)

### Installing dependencies
Install all required packages:
```bash
npm install express express-session body-parser cors
```

Alternatively, the dependencies can be automatically derived from the `package.json` file:
```bash
npm install
```

---

## 🚀 Operation and demonstration

Execute the following steps in a dedicted terminal window to demonstrate the full integration pipeline:

### Step 1: start the Express REST API server
Launch the backend module. The server will generate ephemeral key pairs upon start (trust store) and will save them in `demo-keys.json`:
```bash
node eudi-verifier-server.js
```
*Output:* Server is running at `http://localhost:3000`

### Step 2: open the frontend in a browser window
Open the `index.html` file in a web browser. Alternatively, navigate to `http://localhost:3000` as this file is also being served by the backend on the `/` route.
1. Click on the button **"Start authentication"**.
2. The system will generate a unique transaction nonce and will display the dynamic **QR code**
3. Frontend will now switch to waiting mode and will poll the session status continuously in the background

### Step 3 (deprecated): execute simulation (test harness script)
Launch the wallet simulator in a new terminal window. The script will obtain the JAR from the server, signs the presentation claim for the mock **Erika Mustermann** ID and will POST the data to the callback interface:
```bash
chmod +x eudi-test-harness.sh
./eudi-test-harness.sh
```

*what is happening behind the scenes?*
* The script will read the transaction parameters from the QR code
* The script will generate the hash values for the identity disclosures (first name, last name, ...)
* The script will generated the **Key Binding JWT** and will link it to the server nonce
* The callback (`direct_post`) will be sent to the Express backend

**Result(s):** 
* Success message will be displayed in the terminal, alongside the verified JSON profile
* The frontend will automatically display a success message as a result of the polling succession a will dsiplay the digital ID of the mock identity (incl. the audit report)

### Step 4: launch the re-written test harness / simulator
The test harness can be executed in the desired simulation mode.

#### Option A: end-to-end flow (dynamic issuance & encrypted presentation)
This mode simulates the complete flow end-to-end:
1. wallet obtains a freshly signed PID that is bound to a hardware device key from the issuer (`/api/issuance`)
2. wallet will present the PID as JWE to the RP (`/api/presentation`)

```bash
node eudi-test-harness.js --mode=3
```

#### Option B: mDL presentation simulation
This mode simulates the mDL integration:
1. client generates a `SessionTranscript` with server nonce
2. mDL data (Erika Mustermann) is packed into a binary `DeviceResponse` CBOR dokument, which is then being encrypted and sent to the server via `direct_post.jwt`
3. server helper will decrypt the data, parse the CBOR structure and extract the mDL claims

```bash
node eudi-test-harness.js --mode=4
```

#### Option C: encrypted JWE presentation
This mode simulates the onboarding scenario where the wallet is already in possession of a PID and only presents it to a requester (RP).

```bash
node eudi-test-harness.js --mode=2
```

#### Option D: unencrypted presentation
Simulateds a simple unencrypted presentation session using mock dara.

```bash
node eudi-test-harness.js --mode=1
```

*Result*: server will verify the signatures and PoPs. Runtime statistics will be presented upon session completion.

---

## 🔒 Verification stages

### 4 pillars of verification
The verification actions in `eudi-verifier-helper-v2.js` are in accordance with the eIDAS 2.0 framework:

1. **Pillar 1: Issuer Authenticity:** The verifier will check the cryptographic signature of the SD-JWT against the federal trust list. It will calculate the SHA-256 hashes of the disclosures and will compare those with the hashing array provided by the issuer.
2. **Pillar 2: Device & Key Binding:** Verifies the *Key-Binding-JWT* that as been signed with the private key via the WSCD. It will be checked whether the nonce matches the transaction nonce (replay protecion) and whether the `client_id` corresponds to the RP (phishing protection)
3. **Pillar 3: Revocation Status:** The module will parse the `status` claim in the TSL format and will prepare the bit position checks to facilitate real-time revocation checks.
4. **Pillar 4: Wallet Validation & Authenticity:** The script verifies the **WIA** JWT of the wallet issuer to assert that the wallet app is genuine.

### OpenID4VCI security mechanisms
* **DPoP / Sender Constrainting**: forces the binding of unencrypted access tokens to the wallet identity
* **Proof of Possession (PoP)**: checks if the requesting device is in control of the private key to which the credential shall be tied by signing the `c_nonce` via the device (`application/openid4vci-proof+jwt`)

---

## 📄 License
This project is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) license.
