const session = require('express-session');

function setCookies(res) {
  // ruleid: patronus-insecure-cookie-httponly-false
  res.cookie('sid', token, { httpOnly: false });

  // ruleid: patronus-insecure-cookie-secure-false
  res.cookie('sid', token, { secure: false, httpOnly: true });

  // ok: patronus-insecure-cookie-httponly-false
  // ok: patronus-insecure-cookie-secure-false
  res.cookie('sid', token, { httpOnly: true, secure: true, sameSite: 'strict' });
}

// ruleid: patronus-insecure-cookie-secure-false
app.use(session({ secret: s, cookie: { secure: false } }));

// ok: patronus-insecure-cookie-httponly-false
app.use(session({ secret: s, cookie: { httpOnly: true, secure: true } }));
