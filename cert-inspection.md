# How to inspect X509 certificates

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