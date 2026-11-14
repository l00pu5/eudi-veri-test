# How to inspect X509 certificates

- if cert is available as DER instead of PEM, the OpenSSL param `-inform DER` is required

## Dumping the complete cert content

```bash
openssl x509 -in cert.pem -text -noout
```

## Inspecting the validity period

```bash
openssl x509 -in cert.pem -dates -noout
```

## Inspecting subject / SAN

### Subject / Common Name (CN)
```bash
openssl x509 -in cert.pem -subject -noout
```

### Subject Alternative Name (SAN)
```bash
openssl x509 -in cert.pem -ext subjectAltName -noout
```

## Inspecting certificate issuer
```bash
openssl x509 -in cert.pem -issuer -noout
```

## Inspecting certificate usage (extensions)
```bash
openssl x509 -in cert.pem -ext keyUsage,extendedKeyUsage -noout
```

## Check whether cert is CA (=allowed to issue certificates)
```bash
openssl x509 -in cert.pem -ext basicConstraints -noout
```

## Check fingerprint & serial

### Check serial (e.g. for search in CRLs)
```bash
openssl x509 -in cert.pem -serial -noout
```

### Check fingerprint (SHA-256)
```bash
openssl x509 -in cert.pem -fingerprint -sha256 -noout
```

## Calculate clien_id from WRPAC
```bash
echo -n "x509_hash:" && openssl x509 -inform DER -in access_certificate.cer -outform DER | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\n'
```