import type { Finding, Severity } from "./types";

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  kind: "secret" | "sast";
  description: string;
  remediation: string;
  test: (line: string, file: string) => boolean;
  redact?: boolean;
}

const SECRET_FILES = /(\.env|\.pem|\.key|credentials|\.p12)$/i;
const CODE_FILES = /\.(js|jsx|ts|tsx|mjs|cjs|py|go|rb|php|java|cs|rs|sh|yml|yaml|json|env|tf|vue)$/i;

const RULES: Rule[] = [
  {
    id: "secret.aws-access-key",
    title: "Chave de acesso AWS exposta",
    severity: "critical",
    kind: "secret",
    description: "Padrão AKIA de Access Key ID da AWS encontrado no código.",
    remediation: "Revogue a chave no IAM e mova credenciais para um cofre / variáveis de ambiente.",
    test: (l) => /\bAKIA[0-9A-Z]{16}\b/.test(l),
    redact: true,
  },
  {
    id: "secret.github-token",
    title: "Token GitHub exposto",
    severity: "critical",
    kind: "secret",
    description: "Token clássico ou fine-grained do GitHub detectado.",
    remediation: "Revogue o token em GitHub Settings → Developer settings e use secrets de CI.",
    test: (l) => /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/.test(l) || /\bgithub_pat_[A-Za-z0-9_]{20,}\b/.test(l),
    redact: true,
  },
  {
    id: "secret.private-key",
    title: "Chave privada em texto",
    severity: "critical",
    kind: "secret",
    description: "Bloco PEM de chave privada versionado no repositório.",
    remediation: "Remova o arquivo do git, rotacione a chave e use um secret manager.",
    test: (l) => /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/.test(l),
    redact: true,
  },
  {
    id: "secret.stripe",
    title: "Chave secreta Stripe",
    severity: "critical",
    kind: "secret",
    description: "sk_live/sk_test encontrado em fonte.",
    remediation: "Rotacione a chave no dashboard Stripe e carregue-a só no servidor.",
    test: (l) => /\bsk_(live|test)_[A-Za-z0-9]{16,}\b/.test(l),
    redact: true,
  },
  {
    id: "secret.slack",
    title: "Token Slack",
    severity: "high",
    kind: "secret",
    description: "Token Slack (xox-) versionado.",
    remediation: "Revogue o token e use variáveis de ambiente.",
    test: (l) => /\bxox[baprs]-/.test(l),
    redact: true,
  },
  {
    id: "secret.generic-assignment",
    title: "Segredo hardcoded",
    severity: "high",
    kind: "secret",
    description: "Atribuição de api_key / secret / password com literal.",
    remediation: "Substitua o literal por variável de ambiente e rotacione o valor.",
    test: (l) =>
      /(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\s*[:=]\s*['"][^'"]{8,}['"]/i.test(
        l,
      ) && !/process\.env|os\.environ|import\.meta\.env/.test(l),
    redact: true,
  },
  {
    id: "secret.connection-string",
    title: "Connection string com senha",
    severity: "critical",
    kind: "secret",
    description: "URI de banco ou serviço com credencial embutida.",
    remediation: "Use um secret manager. Nunca commite URIs com senha.",
    test: (l) => /\b[a-z]+:\/\/[^:\s\/]+:[^@\s\/]+@/i.test(l),
    redact: true,
  },
  {
    id: "sast.eval",
    title: "Uso de eval / Function",
    severity: "high",
    kind: "sast",
    description: "eval ou new Function executam strings como código — vetor clássico de RCE.",
    remediation: "Substitua por parsing JSON, mapas ou uma DSL explícita.",
    test: (l, f) => /\.(js|ts|tsx|mjs)$/.test(f) && /\beval\s*\(|new Function\s*\(/.test(l),
  },
  {
    id: "sast.innerhtml",
    title: "innerHTML / document.write",
    severity: "high",
    kind: "sast",
    description: "Injeção HTML no DOM sem sanitização — XSS.",
    remediation: "Use textContent ou uma biblioteca de sanitização (DOMPurify).",
    test: (l, f) => /\.(js|ts|tsx|jsx)$/.test(f) && /\.(innerHTML|outerHTML)\s*=|document\.write\s*\(/.test(l),
  },
  {
    id: "sast.dangerously",
    title: "dangerouslySetInnerHTML",
    severity: "medium",
    kind: "sast",
    description: "React renderiza HTML cru. Se a origem não for confiável, vira XSS.",
    remediation: "Sanitize o HTML ou evite a prop.",
    test: (l, f) => /\.(jsx|tsx)$/.test(f) && /dangerouslySetInnerHTML/.test(l),
  },
  {
    id: "sast.child-process",
    title: "Comando de shell interpolado",
    severity: "critical",
    kind: "sast",
    description: "child_process / os.system com interpolação — command injection.",
    remediation: "Passe argumentos em array, nunca concatene a string do shell.",
    test: (l) =>
      (/child_process|execSync|spawnSync/.test(l) && /`[^`]*\$\{/.test(l)) ||
      /os\.system\s*\(|subprocess\.(call|Popen|run)\([^)]*shell\s*=\s*True/.test(l),
  },
  {
    id: "sast.sql-concat",
    title: "SQL concatenado",
    severity: "critical",
    kind: "sast",
    description: "Query montada por concatenação/f-string — SQL injection.",
    remediation: "Use parâmetros ($1, ?, %s) ou um query builder.",
    test: (l) =>
      /(SELECT|INSERT|UPDATE|DELETE|DROP)\s+/i.test(l) &&
      /(\+|`\$\{|f["'].*\{|fmt\.Sprintf)/.test(l),
  },
  {
    id: "sast.pickle",
    title: "pickle.loads inseguro",
    severity: "critical",
    kind: "sast",
    description: "Deserializar pickle de fonte não confiável executa código arbitrário.",
    remediation: "Use JSON. Nunca unpickle dados de usuário.",
    test: (l, f) => /\.py$/.test(f) && /pickle\.loads?\s*\(/.test(l),
  },
  {
    id: "sast.yaml-load",
    title: "yaml.load sem Loader",
    severity: "high",
    kind: "sast",
    description: "yaml.load legado pode instanciar objetos Python arbitrários.",
    remediation: "Use yaml.safe_load.",
    test: (l, f) => /\.py$/.test(f) && /yaml\.load\s*\(/.test(l) && !/safe_load|Loader\s*=/.test(l),
  },
  {
    id: "sast.md5",
    title: "Hash fraco para segredo",
    severity: "medium",
    kind: "sast",
    description: "MD5/SHA1 usados junto de password/token.",
    remediation: "Use argon2id, bcrypt ou SHA-256+HMAC conforme o caso.",
    test: (l) =>
      /(md5|sha1)\s*\(/i.test(l) && /(password|passwd|secret|token)/i.test(l),
  },
  {
    id: "sast.tls-off",
    title: "Validação TLS desligada",
    severity: "high",
    kind: "sast",
    description: "rejectUnauthorized: false / verify=False permite MITM.",
    remediation: "Mantenha a verificação de certificado ligada.",
    test: (l) => /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED/.test(l),
  },
  {
    id: "sast.cors-star",
    title: "CORS aberto",
    severity: "medium",
    kind: "sast",
    description: "Access-Control-Allow-Origin: * com credenciais ou em API autenticada.",
    remediation: "Restrinja origens explícitas.",
    test: (l) => /Access-Control-Allow-Origin['":\s]+\*/.test(l) || /origin:\s*['"]\*['"]/.test(l),
  },
  {
    id: "sast.debug-true",
    title: "Debug ligado em produção",
    severity: "medium",
    kind: "sast",
    description: "DEBUG = True / app.debug = True vaza stack traces.",
    remediation: "Force debug off fora de desenvolvimento.",
    test: (l) => /DEBUG\s*=\s*True|app\.debug\s*=\s*True/.test(l),
  },
  {
    id: "sast.math-random-token",
    title: "Math.random para token",
    severity: "medium",
    kind: "sast",
    description: "PRNG não criptográfico usado para token/secret/password.",
    remediation: "Use crypto.randomUUID / crypto.getRandomValues.",
    test: (l) => /Math\.random/.test(l) && /(token|secret|password|otp|nonce)/i.test(l),
  },
  {
    id: "sast.path-traversal",
    title: "Caminho montado com input",
    severity: "high",
    kind: "sast",
    description: "fs / sendFile com concatenação — path traversal.",
    remediation: "Normalize o path e recuse '..'.",
    test: (l) => /(readFile|sendFile|createReadStream)\s*\([^)]*\+|path\.join\([^)]*req\.(query|params|body)/.test(l),
  },
  {
    id: "sast.jwt-none",
    title: "JWT com algoritmo none / HS256 frágil",
    severity: "high",
    kind: "sast",
    description: "Algoritmo none ou verify desligado aceita token forjado.",
    remediation: "Force algorithms: ['RS256'] ou HS256 com segredo forte e ignoreExpiration: false.",
    test: (l) => /jwt\.(verify|decode)\s*\(/.test(l) && /(algorithms:\s*\[['"]none['"]\]|ignoreExpiration\s*:\s*true)/.test(l),
  },
  {
    id: "sast.insecure-cookie",
    title: "Cookie sem flags de segurança",
    severity: "medium",
    kind: "sast",
    description: "httpOnly/secure ausentes em cookie de sessão.",
    remediation: "Defina httpOnly, secure e sameSite=lax/strict.",
    test: (l) => /res\.cookie\s*\(/.test(l) && !/httpOnly|secure/.test(l),
  },
  {
    id: "sast.proto-pollution",
    title: "Merge inseguro de objeto",
    severity: "high",
    kind: "sast",
    description: "Object.assign / spread de req.body no protótipo — prototype pollution.",
    remediation: "Use Object.create(null) ou bibliotecas que bloqueiam __proto__.",
    test: (l) => /Object\.assign\s*\(\s*\{\s*\}?\s*,\s*req\.(body|query)/.test(l),
  },
  {
    id: "sast.ssrf",
    title: "Fetch de URL controlada",
    severity: "high",
    kind: "sast",
    description: "fetch/axios/request com URL vinda do request — SSRF.",
    remediation: "Allowlist de hosts e bloqueie IPs privados.",
    test: (l) => /(fetch|axios|got|request)\s*\(\s*(req\.(query|body|params)|.*url)/i.test(l) && /req\.(query|body|params)/.test(l),
  },
];

const COPYLEFT = /\b(gpl-?3|agpl|sspl|commons clause)\b/i;

export function scanCodeFiles(files: { path: string; content: string }[]): Finding[] {
  const findings: Finding[] = [];
  let scanned = 0;
  for (const file of files) {
    const path = file.path.replaceAll("\\", "/");
    if (!CODE_FILES.test(path) && !SECRET_FILES.test(path) && !path.endsWith(".env")) continue;
    scanned += 1;
    if (scanned > 250) break;
    const content = file.content.length > 400_000 ? file.content.slice(0, 400_000) : file.content;
    const lines = content.split(/\r?\n/);
    lines.forEach((line, i) => {
      for (const rule of RULES) {
        try {
          if (!rule.test(line, path)) continue;
        } catch {
          continue;
        }
        findings.push({
          id: `${rule.id}:${path}:${i + 1}`,
          kind: rule.kind,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          file: path,
          line: i + 1,
          snippet: rule.redact ? redact(line) : line.trim().slice(0, 220),
          remediation: rule.remediation,
        });
      }
    });
  }
  return findings;
}

export function licenseFindings(license: string | undefined, pkgName: string): Finding[] {
  if (!license) return [];
  if (!COPYLEFT.test(license)) return [];
  return [
    {
      id: `license:${pkgName}`,
      kind: "license",
      severity: "medium",
      title: `Licença copyleft em ${pkgName}`,
      description: `${pkgName} declara ${license}. Licenças copyleft fortes podem obrigar divulgação do fonte.`,
      packageName: pkgName,
      remediation: "Confirme compatibilidade jurídica antes de distribuir o binário.",
    },
  ];
}

function redact(line: string): string {
  return line
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "AKIA••••••••••••")
    .replace(/\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{8,}/g, "$1_••••")
    .replace(/\bsk_(live|test)_[A-Za-z0-9]+/g, "sk_$1_••••")
    .replace(/(['"][^'"]{4})[^'"]{4,}(['"])/g, "$1••••$2")
    .replace(/:\/\/[^@\s]+@/g, "://••••@")
    .trim()
    .slice(0, 220);
}
