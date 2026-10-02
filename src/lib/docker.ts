import type { Finding } from "./types";

export function scanDockerFiles(files: { path: string; content: string }[]): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    const path = file.path.replaceAll("\\", "/");
    if (!/(^|\/)Dockerfile[^/]*$|(^|\/)docker-compose\.ya?ml$/.test(path)) continue;
    const lines = file.content.split(/\r?\n/);
    let hasUser = false;
    lines.forEach((line, i) => {
      const t = line.trim();
      if (/^USER\s+/i.test(t) && !/^USER\s+0\b|^USER\s+root\b/i.test(t)) hasUser = true;
      if (/^FROM\s+\S+:latest\b/i.test(t) || /^FROM\s+\S+\s*$/i.test(t)) {
        findings.push({
          id: `docker.latest:${path}:${i + 1}`,
          kind: "hygiene",
          severity: "medium",
          title: "Imagem Docker sem digest/tag pinada",
          description: "FROM …:latest (ou sem tag) torna o build irreprodutível e pode puxar uma imagem comprometida.",
          file: path,
          line: i + 1,
          snippet: t.slice(0, 200),
          remediation: "Pin a tag semântica e, se possível, o digest sha256.",
        });
      }
      if (/curl\s+[^\n]+\\|\s*sh|wget\s+[^\n]+\|\s*(ba)?sh/i.test(t)) {
        findings.push({
          id: `docker.pipe-sh:${path}:${i + 1}`,
          kind: "sast",
          severity: "high",
          title: "curl | sh no Dockerfile",
          description: "Instalar via pipe para shell executa código remoto sem verificação.",
          file: path,
          line: i + 1,
          snippet: t.slice(0, 200),
          remediation: "Baixe o artefato, verifique checksum e instale em passo separado.",
        });
      }
      if (/^ADD\s+/i.test(t) && !/https?:/i.test(t)) {
        findings.push({
          id: `docker.add:${path}:${i + 1}`,
          kind: "hygiene",
          severity: "low",
          title: "ADD em vez de COPY",
          description: "ADD extrai arquivos e aceita URLs — COPY é o padrão mais previsível.",
          file: path,
          line: i + 1,
          snippet: t.slice(0, 200),
          remediation: "Troque ADD por COPY salvo quando a extração for intencional.",
        });
      }
      if (/^ENV\s+.*=.+/i.test(t) && /(SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE)/i.test(t)) {
        findings.push({
          id: `docker.env-secret:${path}:${i + 1}`,
          kind: "secret",
          severity: "critical",
          title: "Segredo em ENV do Docker",
          description: "Credencial gravada na imagem. Qualquer um com o layer lê o valor.",
          file: path,
          line: i + 1,
          snippet: t.replace(/=.*/, "=••••"),
          remediation: "Passe segredos em runtime (BuildKit secret, orquestrador, vault).",
        });
      }
    });
    if (!hasUser && /Dockerfile/i.test(path)) {
      findings.push({
        id: `docker.user:${path}`,
        kind: "sast",
        severity: "medium",
        title: "Container roda como root",
        description: "Sem USER não-root, um RCE vira root no container.",
        file: path,
        remediation: "Adicione um USER não privilegiado no final do Dockerfile.",
      });
    }
  }
  return findings;
}
