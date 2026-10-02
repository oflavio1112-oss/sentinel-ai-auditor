import type { ScanReport } from "./types";

export function toMarkdown(report: ScanReport): string {
  const lines = [
    `# Sentinel AI — relatório`,
    ``,
    `**Alvo:** ${report.title}`,
    `**Quando:** ${report.createdAt}`,
    `**Risco:** ${report.riskScore}/100`,
    `**Pacotes:** ${report.stats.packages} · **Achados:** ${report.stats.findings}`,
    `**Severidade:** crítico ${report.stats.critical} · alto ${report.stats.high} · médio ${report.stats.medium} · baixo ${report.stats.low}`,
    ``,
  ];
  if (report.aiBrief) {
    lines.push(`## Briefing`, ``, report.aiBrief, ``);
  }
  lines.push(`## Achados`, ``);
  for (const f of report.findings) {
    lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
    if (f.packageName) lines.push(`- Pacote: \`${f.packageName}${f.packageVersion ? `@${f.packageVersion}` : ""}\``);
    if (f.osvId) lines.push(`- OSV: ${f.osvId}`);
    if (f.file) lines.push(`- Arquivo: \`${f.file}:${f.line ?? ""}\``);
    if (f.cvss != null) lines.push(`- CVSS: ${f.cvss}`);
    if (f.fixedVersion) lines.push(`- Corrigido em: \`${f.fixedVersion}\``);
    lines.push(`- ${f.description}`);
    if (f.remediation) lines.push(`- Correção: ${f.remediation}`);
    lines.push(``);
  }
  if (report.notes.length) {
    lines.push(`## Notas`, ``, ...report.notes.map((n) => `- ${n}`), ``);
  }
  return lines.join("\n");
}

export function toSarif(report: ScanReport): string {
  const results = report.findings.map((f) => {
    const level = f.severity === "critical" || f.severity === "high" ? "error" : f.severity === "info" ? "note" : "warning";
    const loc = f.file
      ? {
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: { startLine: f.line ?? 1, snippet: f.snippet ? { text: f.snippet } : undefined },
              },
            },
          ],
        }
      : {};
    return {
      ruleId: f.osvId || f.kind,
      level,
      message: { text: `${f.title}. ${f.description}`.slice(0, 2000) },
      ...loc,
    };
  });
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "Sentinel AI", informationUri: "https://osv.dev", version: "1.0.0" } },
          results,
        },
      ],
    },
    null,
    2,
  );
}

export function toCycloneDx(report: ScanReport): string {
  const components = report.packages.map((p) => ({
    type: "library",
    name: p.name,
    version: p.version ?? undefined,
    purl: p.purl,
    licenses: p.license ? [{ license: { id: p.license } }] : undefined,
    scope: p.scope === "dev" ? "excluded" : "required",
  }));
  const vulnerabilities = report.findings
    .filter((f) => f.kind === "vuln" || f.kind === "malware")
    .map((f) => ({
      id: f.osvId ?? f.id,
      source: { name: "OSV.dev", url: f.osvId ? `https://osv.dev/vulnerability/${f.osvId}` : "https://osv.dev" },
      ratings: f.cvss != null ? [{ method: "CVSSv3", score: f.cvss, severity: f.severity.toUpperCase() }] : undefined,
      description: f.description,
      recommendation: f.remediation,
      affects: f.packageName ? [{ ref: f.packageName }] : undefined,
    }));
  return JSON.stringify(
    {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      version: 1,
      metadata: {
        timestamp: report.createdAt,
        tools: [{ vendor: "Sentinel AI", name: "sentinel-ai-auditor", version: "1.0.0" }],
        component: { type: "application", name: report.title },
      },
      components,
      vulnerabilities,
    },
    null,
    2,
  );
}
