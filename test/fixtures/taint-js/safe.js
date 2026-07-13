// Sanitized paths -> should NOT be flagged by the taint tracker.
function safeHandler(req) {
  const raw = req.query.name;
  const clean = escape(raw);
  db.query('SELECT * FROM t WHERE name = ' + clean);

  const id = parseInt(req.query.id, 10);
  db.query('SELECT * FROM t WHERE id = ' + id);
}

module.exports = { safeHandler };
