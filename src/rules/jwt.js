const jwt = require('jsonwebtoken');

function verifyNone(token) {
  // ruleid: clipeus-jwt-algorithm-none
  return jwt.verify(token, key, { algorithms: ['none'] });
}

function signNone(payload) {
  // ruleid: clipeus-jwt-algorithm-none
  return jwt.sign(payload, key, { algorithm: 'none' });
}

function signHardcoded(payload) {
  // ruleid: clipeus-jwt-hardcoded-secret
  return jwt.sign(payload, 'super-secret-key', { expiresIn: '1h' });
}

function verifyHardcoded(token) {
  // ruleid: clipeus-jwt-hardcoded-secret
  return jwt.verify(token, 'super-secret-key');
}

function signNoExpiry(payload) {
  // ruleid: clipeus-jwt-missing-expiration
  return jwt.sign(payload, process.env.JWT_SECRET);
}

function signSafe(payload) {
  // ok: clipeus-jwt-missing-expiration
  // ok: clipeus-jwt-hardcoded-secret
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m', algorithm: 'HS256' });
}

function verifySafe(token) {
  // ok: clipeus-jwt-algorithm-none
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

module.exports = { verifyNone, signNone, signHardcoded, verifyHardcoded, signNoExpiry, signSafe, verifySafe };
