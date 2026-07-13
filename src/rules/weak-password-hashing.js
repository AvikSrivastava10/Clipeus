const crypto = require('crypto');

function hashPasswordMd5(password) {
  // ruleid: patronus-weak-password-hash-js
  return crypto.createHash('md5').update(password).digest('hex');
}

function hashPwdSha1(pwd) {
  // ruleid: patronus-weak-password-hash-js
  return crypto.createHash('sha1').update(pwd).digest('hex');
}

function hashUserPasswordSha256(userPassword) {
  // ruleid: patronus-weak-password-hash-js
  return crypto.createHash('sha256').update(userPassword).digest('hex');
}

function checksumFile(fileData) {
  // ok: patronus-weak-password-hash-js
  return crypto.createHash('sha256').update(fileData).digest('hex');
}
