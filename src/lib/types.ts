export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingKind = "vuln" | "malware" | "secret" | "sast" | "license" | "hygiene";

export type DepScope = "direct" | "dev" | "optional" | "peer" | "transitive";

export type Ecosystem =
  | "npm"
  | "PyPI"
  | "Go"
  | "crates.io"
  | "Maven"
  | "NuGet"
  | "RubyGems"
  | "Packagist"
  | "Pub"
  | "Hex"
  | "GitHub Actions"
  | "unknown";

export interface ScannedPackage {
  name: string;
  version: string | null;
  ecosystem: Ecosystem;
  scope: DepScope;
  purl?: string;
  license?: string;
  unpinned?: boolean;
}

export interface Finding {
  id: string;
  kind: FindingKind;
  severity: Severity;
  title: string;
  description: string;
  packageName?: string;
  packageVersion?: string;
  ecosystem?: Ecosystem;
  aliases?: string[];
  cvss?: number;
  fixedVersion?: string;
  file?: string;
  line?: number;
  snippet?: string;
  remediation?: string;
  references?: { url: string; label?: string }[];
  scope?: DepScope;
  cwe?: string[];
  malicious?: boolean;
  osvId?: string;
}

export interface ScanStats {
  packages: number;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  vulns: number;
  malware: number;
  secrets: number;
  sast: number;
}

export type SourceKind = "manifest" | "code" | "project" | "github" | "mixed";

export interface ScanReport {
  id: string;
  createdAt: string;
  title: string;
  sourceKind: SourceKind;
  packages: ScannedPackage[];
  findings: Finding[];
  stats: ScanStats;
  riskScore: number;
  notes: string[];
  durationMs: number;
  aiBrief?: string;
}

export interface ScanSummary {
  id: string;
  createdAt: string;
  title: string;
  sourceKind: SourceKind;
  packageCount: number;
  findingCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  riskScore: number;
  remote?: boolean;
  top?: Pick<Finding, "id" | "kind" | "severity" | "title" | "packageName" | "osvId" | "fixedVersion">[];
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function emptyStats(): ScanStats {
  return {
    packages: 0,
    findings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    vulns: 0,
    malware: 0,
    secrets: 0,
    sast: 0,
  };
}

export function computeStats(packages: ScannedPackage[], findings: Finding[]): ScanStats {
  const stats = emptyStats();
  stats.packages = packages.length;
  stats.findings = findings.length;
  for (const f of findings) {
    stats[f.severity] += 1;
    if (f.kind === "vuln") stats.vulns += 1;
    if (f.kind === "malware" || f.malicious) stats.malware += 1;
    if (f.kind === "secret") stats.secrets += 1;
    if (f.kind === "sast") stats.sast += 1;
  }
  return stats;
}

export function computeRiskScore(stats: ScanStats): number {
  const raw =
    stats.malware * 38 +
    stats.critical * 22 +
    stats.high * 10 +
    stats.medium * 4 +
    stats.low * 1 +
    stats.secrets * 8;
  return Math.max(0, Math.min(100, raw));
}
