import { compareSemver } from "./utils";
import type { Finding, ScannedPackage } from "./types";

export async function outdatedFindings(packages: ScannedPackage[]): Promise<{ findings: Finding[]; notes: string[] }> {
  const direct = packages.filter((p) => p.ecosystem === "npm" && p.version && (p.scope === "direct" || p.scope === "dev"));
  const slice = direct.slice(0, 24);
  if (!slice.length) return { findings: [], notes: [] };

  const findings: Finding[] = [];
  let checked = 0;
  await Promise.all(
    slice.map(async (pkg) => {
      try {
        const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg.name)}/latest`, {
          headers: { Accept: "application/json" },
        });
        if (!res.ok) return;
        checked += 1;
        const body = (await res.json()) as { version?: string };
        const latest = body.version;
        if (!latest || !pkg.version) return;
        if (compareSemver(latest, pkg.version) <= 0) return;
        const majorLag = major(latest) > major(pkg.version);
        findings.push({
          id: `outdated:${pkg.name}@${pkg.version}`,
          kind: "hygiene",
          severity: majorLag ? "medium" : "low",
          title: `${pkg.name} desatualizado`,
          description: `Instalado ${pkg.version}; latest no npm é ${latest}.`,
          packageName: pkg.name,
          packageVersion: pkg.version,
          ecosystem: "npm",
          fixedVersion: latest,
          remediation: `Atualize para ${latest} e rode o scan de novo.`,
        });
      } catch {
        /* registry flaky */
      }
    }),
  );

  return {
    findings,
    notes: [`npm registry: ${checked}/${slice.length} pacotes diretos conferidos contra latest.`],
  };
}

function major(v: string): number {
  return parseInt(v.replace(/^v/, "").split(".")[0] ?? "0", 10) || 0;
}
