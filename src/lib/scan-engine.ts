import { unzipSync } from "fflate";
import { scanDockerFiles } from "./docker";
import { fetchGithubFiles } from "./github";
import { outdatedFindings } from "./outdated";
import { queryOsv } from "./osv";
import { parseLooseText, parseProjectFiles, shouldSkipPath, type ProjectFile } from "./parse-manifest";
import { licenseFindings, scanCodeFiles } from "./sast";
import { supplyFindings } from "./supply-chain";
import { computeRiskScore, computeStats, type ScanReport, type SourceKind } from "./types";
import { uid } from "./utils";

const TEXT_EXT =
  /\.(json|lock|txt|toml|mod|xml|ya?ml|js|jsx|ts|tsx|mjs|cjs|py|go|rb|php|java|cs|rs|env|md|gradle)$/i;

export async function scanText(filename: string, text: string): Promise<ScanReport> {
  const started = Date.now();
  const looksCode = !isManifestName(filename) && !looksLikeManifest(text);
  if (looksCode) {
    const findings = [
      ...scanCodeFiles([{ path: filename || "snippet.txt", content: text }]),
      ...scanDockerFiles([{ path: filename || "snippet.txt", content: text }]),
    ];
    return finalize({
      title: filename || "código",
      sourceKind: "code",
      packages: [],
      findings,
      notes: ["Análise estática local — nenhum manifesto de dependência detectado."],
      started,
    });
  }
  const parsed = parseLooseText(filename, text);
  return runPackages(parsed.title, parsed.kind === "project" ? "project" : "manifest", parsed.packages, parsed.notes, started, [
    { path: filename || parsed.title, content: text },
  ]);
}

export async function scanFiles(files: ProjectFile[], sourceKind: SourceKind, titleHint?: string): Promise<ScanReport> {
  const started = Date.now();
  const filtered = files.filter((f) => !shouldSkipPath(f.path));
  const parsed = parseProjectFiles(filtered);
  return runPackages(titleHint || parsed.title, sourceKind, parsed.packages, parsed.notes, started, filtered);
}

export async function scanZip(buffer: ArrayBuffer, zipName: string): Promise<ScanReport> {
  const unzipped = unzipSync(new Uint8Array(buffer));
  const files: ProjectFile[] = [];
  let total = 0;
  for (const [path, data] of Object.entries(unzipped)) {
    if (!data || shouldSkipPath(path)) continue;
    if (!TEXT_EXT.test(path) && !/(^|\/)(Dockerfile[^/]*|\.env|\.npmrc)$/.test(path)) continue;
    if (data.byteLength > 750_000) continue;
    total += data.byteLength;
    if (total > 6_000_000 || files.length > 400) break;
    files.push({ path, content: new TextDecoder().decode(data) });
  }
  return scanFiles(files, "project", zipName.replace(/\.zip$/i, ""));
}

export async function scanGithubRepo(url: string): Promise<ScanReport> {
  const started = Date.now();
  const fetched = await fetchGithubFiles(url);
  const parsed = parseProjectFiles(fetched.files);
  return runPackages(
    fetched.title,
    "github",
    parsed.packages,
    [...fetched.notes, ...parsed.notes],
    started,
    fetched.files,
  );
}

async function runPackages(
  title: string,
  sourceKind: SourceKind,
  packages: ScanReport["packages"],
  notes: string[],
  started: number,
  files: ProjectFile[],
): Promise<ScanReport> {
  const [{ findings: osvFindings, notes: osvNotes }, outdated] = await Promise.all([
    packages.length ? queryOsv(packages) : Promise.resolve({ findings: [], notes: [] }),
    outdatedFindings(packages),
  ]);
  const sast = scanCodeFiles(files);
  const docker = scanDockerFiles(files);
  const licenses = packages.flatMap((p) => licenseFindings(p.license, p.name));
  const supply = supplyFindings(packages);
  const hygiene = packages
    .filter((p) => p.unpinned)
    .slice(0, 25)
    .map((p) => ({
      id: `pin:${p.ecosystem}:${p.name}`,
      kind: "hygiene" as const,
      severity: "low" as const,
      title: `${p.name} sem versão pinada`,
      description: "Ranges abertos tornam o scan e o build não reproduzíveis.",
      packageName: p.name,
      ecosystem: p.ecosystem,
      remediation: "Gere um lockfile e faça pin da versão no manifesto.",
    }));
  const findings = [...osvFindings, ...sast, ...docker, ...licenses, ...hygiene, ...supply, ...outdated.findings];
  return finalize({
    title,
    sourceKind,
    packages,
    findings,
    notes: [...notes, ...osvNotes, ...outdated.notes],
    started,
  });
}

function finalize(input: {
  title: string;
  sourceKind: SourceKind;
  packages: ScanReport["packages"];
  findings: ScanReport["findings"];
  notes: string[];
  started: number;
}): ScanReport {
  const findings = [...input.findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity] || a.title.localeCompare(b.title);
  });
  const stats = computeStats(input.packages, findings);
  return {
    id: uid(),
    createdAt: new Date().toISOString(),
    title: input.title,
    sourceKind: input.sourceKind,
    packages: input.packages,
    findings,
    stats,
    riskScore: computeRiskScore(stats),
    notes: input.notes,
    durationMs: Date.now() - input.started,
  };
}

function isManifestName(name: string): boolean {
  return /(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|requirements\.txt|pyproject\.toml|poetry\.lock|Pipfile(\.lock)?|go\.mod|Cargo\.(toml|lock)|composer\.(json|lock)|Gemfile\.lock|pom\.xml|pubspec\.yaml|Dockerfile)$/i.test(
    name,
  );
}

function looksLikeManifest(text: string): boolean {
  const t = text.trim();
  return (
    (t.startsWith("{") && /("dependencies"|"packages"|"require")/.test(t)) ||
    /^\s*module\s+\S+/m.test(t) ||
    /==\s*\d/.test(t) ||
    t.includes("[dependencies]") ||
    /^FROM\s+\S+/m.test(t)
  );
}
