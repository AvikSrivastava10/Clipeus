const { runCommand } = require('./cmd');

// Cross-file: user input flows into runCommand, which sinks it via child_process.
function handleReq(req, res) {
  const userCmd = req.body.command;
  runCommand(userCmd);
  res.send('ok');
}

// Intra-function: tainted value concatenated into a SQL query.
function directSink(req) {
  const q = req.query.q;
  db.query('SELECT * FROM t WHERE name = ' + q);
}

// Intra-function: eval of user input (full-match sink -> medium confidence).
function evalHandler(req) {
  const expr = req.body.expr;
  eval(expr);
}

module.exports = { handleReq, directSink, evalHandler };
