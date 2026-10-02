import { chunk, compareSemver, mapPool } from "./utils";
import { cvssBaseFromVector, severityFromScore } from "./cvss";
import type { Ecosystem, Finding, ScannedPackage } from "./types";

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns";
const BATCH_SIZE = 80;

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version?: string;
}

interface OsvBatchHit {
  id: string;
  modified?: string;
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: { type?: string; events?: { introduced?: string; fixed?: string; last_affected?: string }[] }[];
  versions?: string[];
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type?: string; score?: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  references?: { type?: string; url?: string }[];
  affected?: OsvAffected[];
}

export async function queryOsv(packages: ScannedPackage[]): Promise<{ findings: Finding[]; notes: string[] }> {
  const notes: string[] = [];
  const queryable = packages.filter((p) => p.ecosystem !== "unknown" && p.name);
  if (queryable.length === 0) return { findings: [], notes };

  const queries: OsvQuery[] = queryable.map((p) => {
    const q: OsvQuery = { package: { name: p.name, ecosystem: p.ecosystem } };
    if (p.version) q.version = p.version;
    return q;
  });

  const hitsPerQuery: OsvBatchHit[][] = [];
  for (const group of chunk(queries, BATCH_SIZE)) {
    const res = await fetch(OSV_BATCH, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: group }),
    });
    if (!res.ok) {
      notes.push(`OSV.dev recusou o lote (${res.status}).`);
      continue;
    }
    const body = (await res.json()) as { results?: { vulns?: OsvBatchHit[] }[] };
    for (const row of body.results ?? []) hitsPerQuery.push(row.vulns ?? []);
  }

  const uniqueIds = [...new Set(hitsPerQuery.flat().map((h) => h.id).filter(Boolean))];
  const records = new Map<string, OsvVuln>();
  const fetched = await mapPool(uniqueIds, 8, async (id) => {
    try {
      const res = await fetch(`${OSV_VULN}/${encodeURIComponent(id)}`);
      if (!res.ok) return null;
      return (await res.json()) as OsvVuln;
    } catch {
      return null;
    }
  });
  for (const rec of fetched) {
    if (rec?.id) records.set(rec.id, rec);
  }

  const findings: Finding[] = [];
  hitsPerQuery.forEach((hits, index) => {
    const pkg = queryable[index];
    if (!pkg) return;
    for (const hit of hits) {
      const rec = records.get(hit.id);
      findings.push(toFinding(pkg, hit.id, rec));
    }
  });

  notes.push(`OSV.dev: ${queryable.length} pacotes consultados, ${uniqueIds.length} avisos únicos.`);
  return { findings, notes };
}

function toFinding(pkg: ScannedPackage, osvId: string, rec: OsvVuln | undefined): Finding {
  const malicious = osvId.startsWith("MAL-") || (rec?.id ?? "").startsWith("MAL-");
  const vector = rec?.severity?.find((s) => s.score)?.score;
  const cvss = vector ? cvssBaseFromVector(vector) : undefined;
  const severity = malicious
    ? "critical"
    : severityFromScore(cvss, rec?.database_specific?.severity);
  const aliases = rec?.aliases ?? [];
  const fixedVersion = suggestFixed(pkg, rec);
  const details = (rec?.details ?? rec?.summary ?? "Vulnerabilidade conhecida no OSV.dev.").slice(0, 900);
  return {
    id: `${osvId}:${pkg.ecosystem}:${pkg.name}@${pkg.version ?? "?"}`,
    kind: malicious ? "malware" : "vuln",
    severity,
    title: rec?.summary || osvId,
    description: details,
    packageName: pkg.name,
    packageVersion: pkg.version ?? undefined,
    ecosystem: pkg.ecosystem,
    aliases,
    cvss,
    fixedVersion,
    remediation: fixedVersion
      ? `Atualize ${pkg.name} para ${fixedVersion} ou mais recente.`
      : `Revise o aviso ${osvId} e aplique o patch recomendado pelo maintainer.`,
    references: (rec?.references ?? [])
      .filter((r) => r.url)
      .slice(0, 6)
      .map((r) => ({ url: r.url!, label: r.type ?? "ref" })),
    scope: pkg.scope,
    cwe: rec?.database_specific?.cwe_ids,
    malicious,
    osvId,
  };
}

function suggestFixed(pkg: ScannedPackage, rec: OsvVuln | undefined): string | undefined {
  if (!rec?.affected) return undefined;
  const fixed: string[] = [];
  for (const a of rec.affected) {
    const sameName = !a.package?.name || a.package.name === pkg.name;
    const sameEco = !a.package?.ecosystem || a.package.ecosystem === pkg.ecosystem;
    if (!sameName || !sameEco) continue;
    for (const range of a.ranges ?? []) {
      for (const ev of range.events ?? []) {
        if (ev.fixed) fixed.push(ev.fixed);
      }
    }
  }
  if (!fixed.length) return undefined;
  const current = pkg.version;
  const newer = current ? fixed.filter((f) => compareSemver(f, current) > 0) : fixed;
  const pool = newer.length ? newer : fixed;
  return pool.sort(compareSemver)[0];
}

export function purlFor(ecosystem: Ecosystem, name: string, version: string | null): string | undefined {
  if (!version) return undefined;
  const map: Partial<Record<Ecosystem, string>> = {
    npm: "npm",
    PyPI: "pypi",
    Go: "golang",
    "crates.io": "cargo",
    Maven: "maven",
    NuGet: "nuget",
    RubyGems: "gem",
    Packagist: "composer",
    Pub: "pub",
    Hex: "hex",
    "GitHub Actions": "github",
  };
  const type = map[ecosystem];
  if (!type) return undefined;
  return `pkg:${type}/${name}@${version}`;
}
