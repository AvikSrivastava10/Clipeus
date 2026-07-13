const express = require('express');
const app = express();

app.get('/a', (req, res) => {
  try {
    doWork();
  } catch (err) {
    // ruleid: patronus-error-stack-to-client-js
    res.status(500).send(err.stack);
  }
});

app.get('/b', (req, res) => {
  try {
    doWork();
  } catch (err) {
    // ruleid: patronus-error-stack-to-client-js
    res.json({ error: err.stack });
  }
});

app.get('/c', (req, res) => {
  try {
    doWork();
  } catch (err) {
    console.error(err);
    // ok: patronus-error-stack-to-client-js
    res.status(500).send('Internal Server Error');
  }
});
