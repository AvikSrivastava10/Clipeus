const cors = require('cors');
const express = require('express');
const app = express();

function setup(res) {
  // ruleid: clipeus-cors-wildcard-origin
  res.header('Access-Control-Allow-Origin', '*');

  // ruleid: clipeus-cors-wildcard-origin
  res.setHeader('Access-Control-Allow-Origin', '*');
}

// ruleid: clipeus-cors-wildcard-origin
app.use(cors({ origin: '*' }));

// ruleid: clipeus-cors-wildcard-origin
app.use(cors({ origin: true, credentials: true }));

// ok: clipeus-cors-wildcard-origin
app.use(cors({ origin: ['https://app.example.com'] }));

function safe(res) {
  // ok: clipeus-cors-wildcard-origin
  res.header('Access-Control-Allow-Origin', 'https://app.example.com');
}
