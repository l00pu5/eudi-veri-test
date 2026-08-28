# 📄 EUDI Wallet Developer Cheat-Sheet: JSON-Strukturen & JWS-Header

Dieses Spickzettel (Cheat-Sheet) dient als kompakte, präzise Referenz für Entwickler zur Implementierung und zum Debugging von **OpenID4VCI (Ausstellung)** und **OpenID4VP (Präsentation)** im nationalen EUDI-Wallet-Ökosystem. Alle Datenstrukturen und Header entsprechen den aktuellen Spezifikationen von **eIDAS 2.0, HAIP 1.0, OpenID4VCI 1.0** und **OpenID4VP 1.0**.

---

## 🛠️ TEIL 1: OpenID4VCI (Ausstellung / Issuance)

### 1.1 Credential Offer (Herausgabeangebot)
Übertragen im QR-Code (by Value) oder per Link über das Schema `openid-credential-offer://`.

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
        "description": "Geben Sie die 4-stellige PIN ein, die Sie per SMS erhalten haben."
      }
    }
  }
}
```

### 1.2 Token Request (Token-Anforderung)
Gesendet per `POST /api/issuance/token` mit einem **DPoP-Proof**-Header im HTTPS-Header.

#### 1.2.1 DPoP-Header (HTTPS-Header: `DPoP`)
Verhindert Session-Hijacking durch Bindung des Requests an den privaten Wallet-Schlüssel.
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

#### 1.2.2 HTTP-POST Request-Body
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
Weist dem Server nach, dass es sich um eine echte, unmanipulierte App handelt (Säule 4).
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

#### 1.2.4 WIA Proof of Possession (WIA-PoP) – Decoded Client Assertion PoP
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

### 1.3 Token Response (Server-Antwort)
```json
{
  "access_token": "access_token_1f9b30c4ef73",
  "token_type": "DPoP",
  "expires_in": 3600,
  "c_nonce": "c_nonce_from_server_for_subsequent_proof_of_possession",
  "c_nonce_expires_in": 300
}
```

### 1.4 Credential Request (Belegabruf)
Gesendet per `POST /api/issuance/credential` mit gültigem DPoP Access Token im `Authorization`-Header (`Authorization: DPoP access_token_1f9b30c4ef73`).

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

#### 1.4.1 Decoded Proof JWT (Belegbesitznachweis / PoP-JWT)
Beweist, dass der Belegbesitz-Schlüssel auf dem Smartphone generiert wurde und unter Kontrolle des Holders steht.
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

## 🔒 TEIL 2: OpenID4VP (Präsentation / Presentation)

### 2.1 QR-Code Deeplink (Verifizierer-Initiierung)
Der QR-Code auf der Weboberfläche deklariert die sichere Endpoint-Auflösung via HTTPS-Schnittstellen.

```text
openid4vp://?client_id=x509_san_dns:client.example.org&request_uri=https%3A%2F%2Fgaining-decaf-word.ngrok-free.dev%2Fapi%2Fpresentation%2Frequest-jwt%3Fsid%3Dsession_8f3d4c...&request_uri_method=get
```

### 2.2 Signed Request Object (JAR - RFC 9101)
Zurückgegeben unter der `request_uri`.

#### 2.2.1 JWS Header (mit X.509 `x5c` Zertifikats-Injektion)
Zwingend erforderlich bei `client_id: x509_san_dns:client.example.org`.

```json
{
  "alg": "ES256",
  "typ": "oauth-authz-req+jwt",
  "x5c": [
    "MIIB9DCCAZqgAwIBAgIUFHpWvV7NGRxON... (Base64-kodiertes X.509 Zertifikat von client.example.org)"
  ]
}
```

#### 2.2.2 Decoded JAR-Request Payload (mit DCQL-Query)
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

### 2.3 direct_post.jwt Callback (Verschlüsselter Callback-POST)
Gesendet per `POST /api/presentation/callback` im **JWE-Kompaktformat** (5 Segmente, Punkt-separiert).

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

#### 2.3.2 Decoded JWE Payload (Nach asynchroner Entschlüsselung)
```json
{
  "vp_token": "<signed_vp_token_containing_claims_and_key_binding>",
  "state": "session_8f3d4c_state"
}
```

---

## 💡 Krypto-Gegenüberstellung: Signatur (JWS) vs. Verschlüsselung (JWE)

*   **JWS (JSON Web Signature):** Sichert den **Ursprung (Authentizität)** und die **Integrität**. Das JAR-Request-Object (JWS) beweist dem Smartphone, dass die Anfrage echt ist. Die Signatur des Holders auf dem Beleg beweist dem Verifizierer, dass der Beleg nicht manipuliert wurde.
*   **JWE (JSON Web Encryption):** Sichert den **Transport (Vertraulichkeit)**. Mittels des elliptischen Sitzungsschlüssels (ECDH) verschlüsselt das Smartphone Erikas Identitätsdaten, sodass sie auf dem Rückkanal vor Abhören geschützt sind (selbst über unverschlüsselte Tunnel-Schnittstellen).
