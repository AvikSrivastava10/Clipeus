const express = require('express');
const crypto = require('crypto');
const app = express();

// ruleid: patronus-webhook-missing-signature-verification
app.post('/webhook/stripe', (req, res) => {
  const event = req.body;
  processEvent(event);
  res.sendStatus(200);
});

app.post('/webhook/github', (req, res) => {
  // A signature check is present, so this handler is NOT flagged.
  const sig = req.headers['x-hub-signature-256'];
  const hmac = crypto.createHmac('sha256', process.env.SECRET);
  const digest = 'sha256=' + hmac.update(req.rawBody).digest('hex');
  // ok: patronus-webhook-missing-signature-verification
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(digest))) {
    return res.sendStatus(401);
  }
  processEvent(req.body);
  res.sendStatus(200);
});

// A non-webhook route is not the target of this rule.
// ok: patronus-webhook-missing-signature-verification
app.post('/users', (req, res) => {
  createUser(req.body);
  res.sendStatus(201);
});
