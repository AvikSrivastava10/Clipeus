const crypto = require('crypto');

function hashPasswordMd5(password) {
  // ruleid: clipeus-weak-password-hash-js
  return crypto.createHash('md5').update(password).digest('hex');
}

function hashPwdSha1(pwd) {
  // ruleid: clipeus-weak-password-hash-js
  return crypto.createHash('sha1').update(pwd).digest('hex');
}

function hashUserPasswordSha256(userPassword) {
  // ruleid: clipeus-weak-password-hash-js
  return crypto.createHash('sha256').update(userPassword).digest('hex');
}

function checksumFile(fileData) {
  // ok: clipeus-weak-password-hash-js
  return crypto.createHash('sha256').update(fileData).digest('hex');
}
