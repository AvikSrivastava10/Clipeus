const session = require('express-session');

function setCookies(res) {
  // ruleid: clipeus-insecure-cookie-httponly-false
  res.cookie('sid', token, { httpOnly: false });

  // ruleid: clipeus-insecure-cookie-secure-false
  res.cookie('sid', token, { secure: false, httpOnly: true });

  // ok: clipeus-insecure-cookie-httponly-false
  // ok: clipeus-insecure-cookie-secure-false
  res.cookie('sid', token, { httpOnly: true, secure: true, sameSite: 'strict' });
}

// ruleid: clipeus-insecure-cookie-secure-false
app.use(session({ secret: s, cookie: { secure: false } }));

// ok: clipeus-insecure-cookie-httponly-false
app.use(session({ secret: s, cookie: { httpOnly: true, secure: true } }));
