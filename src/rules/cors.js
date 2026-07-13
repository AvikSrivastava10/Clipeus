const cors = require('cors');
const express = require('express');
const app = express();

function setup(res) {
  // ruleid: patronus-cors-wildcard-origin
  res.header('Access-Control-Allow-Origin', '*');

  // ruleid: patronus-cors-wildcard-origin
  res.setHeader('Access-Control-Allow-Origin', '*');
}

// ruleid: patronus-cors-wildcard-origin
app.use(cors({ origin: '*' }));

// ruleid: patronus-cors-wildcard-origin
app.use(cors({ origin: true, credentials: true }));

// ok: patronus-cors-wildcard-origin
app.use(cors({ origin: ['https://app.example.com'] }));

function safe(res) {
  // ok: patronus-cors-wildcard-origin
  res.header('Access-Control-Allow-Origin', 'https://app.example.com');
}
