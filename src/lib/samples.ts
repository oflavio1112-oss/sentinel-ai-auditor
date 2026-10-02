export const SAMPLE_PACKAGE_JSON = `{
  "name": "demo-vulneravel",
  "version": "1.0.0",
  "license": "MIT",
  "dependencies": {
    "lodash": "4.17.20",
    "minimist": "1.2.5",
    "axios": "0.21.1",
    "node-fetch": "2.6.0",
    "express": "4.17.1",
    "jsonwebtoken": "8.5.1"
  }
}
`;

export const SAMPLE_REQUIREMENTS = `Django==2.2.13
requests==2.19.1
PyYAML==5.1
Flask==0.12.2
`;

export const SAMPLE_CODE = `// snippet de demonstração — valores oficiais de exemplo, não use em produção
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GITHUB = "ghp_exampletokenvalueforscannerdemo1";
app.get("/search", (req, res) => {
  const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  db.query(q);
  res.send(eval(req.query.expr));
  element.innerHTML = req.query.html;
  require("child_process").exec(\`ls \${req.query.dir}\`);
});
`;
