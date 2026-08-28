Befehls-Spickzettel für Ihr Terminal

Wechseln Sie in Ihrem lokalen Terminal in das Verzeichnis, in dem Sie die Datei abgelegt haben:

1. Zertifikat und privaten Schlüssel generieren:
node eudi-krypto-tool.js gencert --out-key=rp-private-key.pem --out-cert=rp-cert.pem

2. Ein JAR Request Object kryptografisch signieren (JWS):
node eudi-krypto-tool.js sign \
  --key=rp-private-key.pem \
  --cert=rp-cert.pem \
  --payload='{"nonce":"85d5e24a","client_id":"x509_san_dns:client.example.org"}' \
  --out=signed-request.jwt

3. Daten für die Wallet E2E-verschlüsseln (JWE):
node eudi-krypto-tool.js encrypt \
  --pubkey=test-wallet-pubkey.json \
  --payload="Geheime Ausweisdaten..." \
  --out=encrypted-response.jwe

4. Ein empfangenes JWE-Paket entschlüsseln:
node eudi-krypto-tool.js decrypt \
  --key=rp-private-key.pem \
  --jwe=encrypted-response.jwe