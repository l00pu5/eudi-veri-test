# 📄 EUDI Wallet Developer Cheat Sheet: JSON data structures & JWS headers

This cheat sheet shall serve as a compact reference for developers seeking to implement related functionality and for debugging purposes of **OpenID4VCI (issuance)** as well as **OpenID4VP (presentatoon)** transactions.

---

## PART 1: OpenID4VCI (Issuance)

### 1.1 Credential Offer
Will be encoded in the QR code oder via plain URL with schema `openid-credential-offer://`.

```json
{
  "credential_issuer": "https://gaining-decaf-word.ngrok-free.dev/api/issuance",
  "credential_configuration_ids": [
    "PID_SD_JWT_VC"
  ],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "pre-auth-code-789a456bc",
      "tx_code": {
        "length": 4,
        "input_mode": "numeric",
        "description": "Please enter your 4-digit PIN."
      }
    }
  }
}
```

### 1.2 Token Request (Token-Anforderung)
Sent via `POST /api/issuance/token` with a **DPoP Proof** header in the HTTP(S) header.

#### 1.2.1 DPoP header (HTTPS header: `DPoP`)
Prevents session hijacking by binding the request to the private wallet key.
```json
// JOSE Header
{
  "alg": "ES256",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "ShU4Fr3NH7v9TOAc9aYiu9eicdkfVT9ecVCPaPgJrMs",
    "y": "iV0VXASylR0qWoDr_mKUWwzo-M59Wz3QBzpCm4oiXT0"
  }
}
// Payload
{
  "jti": "jti_rand_96bit_randomness_123",
  "htm": "POST",
  "htu": "https://gaining-decaf-word.ngrok-free.dev/api/issuance/token",
  "iat": 1787680000,
  "nonce": "dpop_nonce_from_server_nonce_endpoint"
}
```

#### 1.2.2 HTTP-POST Request Body
```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
  "pre-authorized_code": "pre-auth-code-789a456bc",
  "tx_code": "1234",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "<WIA_JWT_TOKEN_signed_by_WalletProvider>",
  "client_assertion_pop": "<WIA_PoP_JWT_signed_by_WalletInstance>"
}
```

#### 1.2.3 Wallet Instance Attestation (WIA) – Decoded Client Assertion
Proves to the server that the wallet instance is authentic / untampered
```json
// Header
{
  "alg": "ES256",
  "typ": "oauth-client-attestation+jwt",
  "kid": "keys-id-wallet-provider"
}
// Payload
{
  "iss": "https://wallet-provider-backend.eudi-wallet.de",
  "sub": "https://wallet.example.com/instances/12345",
  "wallet_name": "EUDI National Reference Wallet",
  "iat": 1787680000,
  "exp": 1787683600,
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "ShU4Fr3NH7v9TOAc9aYiu9eicdkfVT9ecVCPaPgJrMs",
      "y": "iV0VXASylR0qWoDr_mKUWwzo-M59Wz3QBzpCm4oiXT0"
    }
  }
}
```

#### 1.2.4 WIA Proof of Possession (WIA PoP) – Decoded Client Assertion PoP
```json
// Header
{
  "alg": "ES256",
  "typ": "oauth-client-attestation-pop+jwt"
}
// Payload
{
  "iss": "https://wallet.example.com/instances/12345",
  "aud": "https://gaining-decaf-word.ngrok-free.dev/api/issuance",
  "jti": "d25d00ab-552b-46fc-ae19-98f440f25064",
  "iat": 1787680000,
  "challenge": "challenge_iss_from_issuance_initiate"
}
```

### 1.3 Token Response (Server Rntwort)
```json
{
  "access_token": "access_token_1f9b30c4ef73",
  "token_type": "DPoP",
  "expires_in": 3600,
  "c_nonce": "c_nonce_from_server_for_subsequent_proof_of_possession",
  "c_nonce_expires_in": 300
}
```

### 1.4 Credential Request
Sent via `POST /api/issuance/credential` with valid DPoP Access Token in `Authorization` HTTP header (`Authorization: DPoP access_token_1f9b30c4ef73`).
```json
{
  "credential_configuration_id": "PID_SD_JWT_VC",
  "proofs": {
    "jwt": [
      "<openid4vci_proof_jwt_signed_by_holder_device_key>"
    ]
  }
}
```

#### 1.4.1 Decoded Proof JWT (PoP JWT)
Proves that the PoP key has been generated on the smartphone and is under holder's control.
```json
// Header
{
  "alg": "ES256",
  "typ": "openid4vci-proof+jwt",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "device_key_x_coordinate_base64url...",
    "y": "device_key_y_coordinate_base64url..."
  }
}
// Payload
{
  "aud": "https://gaining-decaf-word.ngrok-free.dev/api/issuance",
  "iat": 1787680000,
  "nonce": "c_nonce_received_in_token_response"
}
```

---

## PART 2: OpenID4VP (Presentation)

### 2.1 QR-Code Deeplink (Verifier Initiation)
```text
openid4vp://?client_id=x509_san_dns:client.example.org&request_uri=https%3A%2F%2Fgaining-decaf-word.ngrok-free.dev%2Fapi%2Fpresentation%2Frequest-jwt%3Fsid%3Dsession_8f3d4c...&request_uri_method=get
```

### 2.2 Signed Request Object (JAR - RFC 9101)
Returned via the `request_uri`.

#### 2.2.1 JWS Header (with X.509 `x5c` Certificate Injection)
Mandatory with `client_id: x509_san_dns:client.example.org`.

```json
{
  "alg": "ES256",
  "typ": "oauth-authz-req+jwt",
  "x5c": [
    "MIIB9DCCAZqgAwIBAgIUFHpWvV7NGRxON... (Base64-encoded X.509 certificate from client.example.org)"
  ]
}
```

#### 2.2.2 Decoded JAR Request Payload (with DCQL-Query)
```json
{
  "iss": "x509_san_dns:client.example.org",
  "aud": "https://self-issued.me/v2",
  "response_type": "vp_token",
  "response_mode": "direct_post.jwt",
  "response_uri": "https://gaining-decaf-word.ngrok-free.dev/api/presentation/callback",
  "client_id": "x509_san_dns:client.example.org",
  "nonce": "session_bound_random_nonce_112233",
  "state": "session_8f3d4c_state",
  "dcql_query": {
    "credentials": [
      {
        "id": "my_identity_credential",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": ["https://credentials.example.com/identity_credential"]
        },
        "claims": [
          { "path": ["given_name"] },
          { "path": ["family_name"] },
          { "path": ["birthdate"] },
          { "path": ["is_over_18"] },
          { "path": ["address"] }
        ]
      }
    ]
  },
  "client_metadata": {
    "jwks": {
      "keys": [
        {
          "kty": "EC",
          "crv": "P-256",
          "x": "ephemeral_verifier_dh_public_x...",
          "y": "ephemeral_verifier_dh_public_y...",
          "kid": "enc-key-1",
          "use": "enc",
          "alg": "ECDH-ES"
        }
      ]
    },
    "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"]
  }
}
```

### 2.3 direct_post.jwt callback (encrypted callback POST)
Sent via `POST /api/presentation/callback` as **JWE** (5 segments, dot-separated).

#### 2.3.1 JWE Protected Header (Segment 1)
```json
{
  "alg": "ECDH-ES",
  "enc": "A128GCM",
  "epk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "ephemeral_wallet_dh_public_x...",
    "y": "ephemeral_wallet_dh_public_y..."
  }
}
```

#### 2.3.2 Decoded JWE Payload (after async decryption)
```json
{
  "vp_token": "<signed_vp_token_containing_claims_and_key_binding>",
  "state": "session_8f3d4c_state"
}
```

---

## Crypto comparison: signature (JWS) vs. encryption (JWE)

*   **JWS (JSON Web Signature)**: Secures the **Origin (Autnenticity)** and the **Integrity**. The JAR Request Object (JWS) proves to the smartphone, that the request is genuine. The holder's signature on the credential proves to the verifier, that the credential hasn't been tampered with.
*   **JWE (JSON Web Encryption)**: Secures the **Tranport**. Identity data are encrypted via elliptic session keys (ECDH) to prevent data disclosure on the backchannel even when transport is occurring via unsecured tunnels.
