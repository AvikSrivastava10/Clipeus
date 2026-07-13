const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

function checkToken(token) {
  // ruleid: patronus-hallucinated-security-api-js
  return jwt.validate(token);
}

function checkPassword(pw, hash) {
  // ruleid: patronus-hallucinated-security-api-js
  return bcrypt.verify(pw, hash);
}

function encryptData(data, key) {
  // ruleid: patronus-hallucinated-security-api-js
  return crypto.encrypt(data, key);
}

function checkPasswordReal(pw, hash) {
  // ok: patronus-hallucinated-security-api-js
  return bcrypt.compare(pw, hash);
}

function verifyTokenReal(token, key) {
  // ok: patronus-hallucinated-security-api-js
  return jwt.verify(token, key);
}
