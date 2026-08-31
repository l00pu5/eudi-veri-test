# Terminal command cheat sheet

1. Generate certificate and private key:
```bash
node eudi-crypto-tool.js gencert --out-key=rp-private-key.pem --out-cert=rp-cert.pem
```

2. Cryptographically sign JAR request object (JWS):
```bash
node eudi-crypto-tool.js sign --key=rp-private-key.pem --cert=rp-cert.pem --payload='{"nonce":"85d5e24a","client_id":"x509_san_dns:client.example.org"}' --out=signed-request.jwt
```

3. Encrypt data for the wallet (JWE):
```bash
node eudi-crypto-tool.js encrypt --pubkey=test-wallet-pubkey.json --payload="secret data..." --out=encrypted-response.jwe
```

4. Decrypt incoming JWE:
```bash
node eudi-crypto-tool.js decrypt --key=rp-private-key.pem --jwe=encrypted-response.jwe
```