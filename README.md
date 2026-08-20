# EUDI Wallet - Relying Party (RP) Test Harness & Integration Simulator (ERP-THIS)

A developer-friendly, vendor-neutral reference framework for implementing and testing a **Relying Party / Verifier** within the nation **EUDI Wallet Ecosystem** in accordance with **eIDAS2.0**.

This repository contains the corresponding Node.js backend, an interactive HTML5-based demo frontend and an automated Bash script to simulate a credential presentation from a wallet instance towards a relying party (RP) using **OpenID4VP** and **IETF SD-JWT VC**.

---

## 📦 Project Components / Modules

The project consists of 4 related modules:

1. **`eudi-verifier-helper-v2.js` (Core Library):**
  * verifies incoming credentials in accordance with the **4 pillars of verification**
  * is based solely on **native Node.js `crypto` module** - no other external dependencies
  * contains a full-blown mockup **Erika Mustermann identity simulation** for testing purposes

2. **`eudi-verifier-server.js` (Express-based REST API):**
  * manages the lifecycle of transient sessions
  * signs and delivers **JAR** (RFC9101) containing **DCQL** queries
  * implements **`direct_post` (HTTP POST)** interface for accepting wallet data asynchronously

3. **`index.html` (Web Frontend):**
  * intuitive user interface for demonstrating the cross-device wallet interaction flow
  * generates QR code with `openid4vp` request
  * conducts real-time polling of fulfilment status
  * visualizes mock identity profile / audit report

4. **`eudi-test-harness.sh` (Bash Test Script / Wallet Simulation):**
  * automates the presentation and validation flow via command line
  * simulates EUDI wallet interaction: retrieves the JAR request, generates SD-JWT VC with holder binding proof + WIA and posts the data to the RP interface

---

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
Launch the backend module. The server will generate ephemeral key pairs upon start (trust store):
```bash
node eudi-verifier-server.js
```
*Output:* Server is running at `http://localhost:3000`

### Step 2: open the frontend in a browser window
Open the `index.html` file in a web browser. Alternatively, navigate to `http://localhost:3000` as this file is also being served by the backend on the `/` route.
1. Click on the button **"Authentisierung starten"**.
2. The system will generate a unique transaction nonce and will display the dynamic **QR code**
3. Frontend will now switch to waiting mode and will poll the session status continuously in the background

### Step 3: execute simulation (test harness script)
Launch the wallet simulator in a new terminal window. The script will obtain the JAR from the server, signs the presentation claim for the mock **Erika Mustermann** ID and will POST the data to the callback interface:
```bash
chmod +x eudi-test-harness.sh
./eudi-test-harness.sh
```

*what is happening behind the scenes?*
* The script will read the transaction parameters from the QR code
* The script will generate the hash values for the identity disclosures (first name, last name, ...)
* The script will generated the **Key Binding JWT** and will link it to the server nonce
* The callack (`direct_post`) will be sent to the Express backend

**Result(s):** 
* Success message will be displayed in the terminal, alongside the verified JSON profile
* The frontend will automatically display a success message as a result of the polling succession a will dsiplay the digital ID of the mock identity (incl. the audit report)

---

## 🔒 Verification stages

The verification actions in `eudi-verifier-helper-v2.js` are in accordance with the eIDAS 2.0 framework:

1. **Pillar 1: Issuer Authenticity:** The verifier will check the cryptographic signature of the SD-JWT against the federal trust list. It will calculate the SHA-256 hashes of the disclosures and will compare those with the hashing array provided by the issuer.
2. **Pillar 2: Device & Key Binding:** Verifies the *Key-Binding-JWT* that as been signed with the private key via the WSCD. It will be checked whether the nonce matches the transaction nonce (replay protecion) and whether the `client_id` corresponds to the RP (phishing protection)
3. **Pillar 3: Revocation Status:** The module will parse the `status` claim in the TSL format and will prepare the bit position checks to facilitate real-time revocation checks.
4. **Pillar 4: Wallet Validation & Authenticity:** The script verifies the **WIA** JWT of the wallet issuer to assert that the wallet app is genuine.

---

## 📄 License
This project is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) license.
