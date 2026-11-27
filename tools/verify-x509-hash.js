#!/usr/bin/env node
const crypto = require('crypto');

function calculateX509Hash(x5cString) {
  if (!x5cString || typeof x5cString !== 'string') {
    throw new Error('Invalid x5c input');
  }

  // input string normalization
  const cleanB64 = x5cString.trim().replace(/^["']|["']$/g, '').replace(/[\r\n\s]/g, '');

  // Convert Base64 (DER) to Buffer
  const derBuffer = Buffer.from(cleanB64, 'base64');

  if (derBuffer.length === 0) {
    throw new Error('Provided x5c string could not be decoded');
  }

  // SHA-256 hash calculation + encoding as Base64URL (no padding)
  const hashBase64Url = crypto.createHash('sha256')
    .update(derBuffer)
    .digest('base64url');

  return `x509_hash:${hashBase64Url}`;
}

function verifyX509Hash(x5cString, expectedClientId) {
  const calculated = calculateX509Hash(x5cString);
  const cleanExpected = expectedClientId ? expectedClientId.trim() : null;
  const isValid = cleanExpected ? (calculated === cleanExpected) : null;

  return {
    isValid,
    calculatedClientId: calculated,
    expectedClientId: cleanExpected
  };
}

// CLI-Modus
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('=== X.509 Client-ID (x509_hash) Validator ===');
    console.log('Usage:');
    console.log('  node verify-x509-hash.js "<x5c-base64-string>"');
    console.log('  node verify-x509-hash.js "<x5c-base64-string>" "<expected_client-id>"');
    console.log('Example:');
    console.log('  node verify-x509-hash.js "MIIB..." "x509_hash:ABC123xyz..."');
    process.exit(1);
  }

  const x5cInput = args[0];
  const expectedClientId = args[1] || null;

  try {
    const result = verifyX509Hash(x5cInput, expectedClientId);
    console.log('---------------------------------------------------------');
    console.log('Calculated Client ID :', result.calculatedClientId);
    if (result.expectedClientId) {
      console.log('Expected Client ID  :', result.expectedClientId);
      console.log('Status               :', result.isValid ? '✅ MATCH' : '❌ MISMATCH');
    }
    console.log('---------------------------------------------------------\n');
  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exit(1);
  }
}

module.exports = {
  calculateX509Hash,
  verifyX509Hash
};
