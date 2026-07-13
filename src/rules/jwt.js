const jwt = require('jsonwebtoken');

function verifyNone(token) {
  // ruleid: patronus-jwt-algorithm-none
  return jwt.verify(token, key, { algorithms: ['none'] });
}

function signNone(payload) {
  // ruleid: patronus-jwt-algorithm-none
  return jwt.sign(payload, key, { algorithm: 'none' });
}

function signHardcoded(payload) {
  // ruleid: patronus-jwt-hardcoded-secret
  return jwt.sign(payload, 'super-secret-key', { expiresIn: '1h' });
}

function verifyHardcoded(token) {
  // ruleid: patronus-jwt-hardcoded-secret
  return jwt.verify(token, 'super-secret-key');
}

function signNoExpiry(payload) {
  // ruleid: patronus-jwt-missing-expiration
  return jwt.sign(payload, process.env.JWT_SECRET);
}

function signSafe(payload) {
  // ok: patronus-jwt-missing-expiration
  // ok: patronus-jwt-hardcoded-secret
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m', algorithm: 'HS256' });
}

function verifySafe(token) {
  // ok: patronus-jwt-algorithm-none
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

module.exports = { verifyNone, signNone, signHardcoded, verifyHardcoded, signNoExpiry, signSafe, verifySafe };
