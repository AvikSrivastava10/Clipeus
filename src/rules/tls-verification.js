const https = require('https');
const axios = require('axios');

function makeAgent() {
  // ruleid: patronus-tls-reject-unauthorized-false
  return new https.Agent({ rejectUnauthorized: false });
}

function axiosClient() {
  // ruleid: patronus-tls-reject-unauthorized-false
  return axios.create({ httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
}

function disableGlobally() {
  // ruleid: patronus-node-tls-reject-env
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

function safeAgent(ca) {
  // ok: patronus-tls-reject-unauthorized-false
  return new https.Agent({ ca, rejectUnauthorized: true });
}

function keepTlsEnabled() {
  // ok: patronus-node-tls-reject-env
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
}
