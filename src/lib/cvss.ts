const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PRU: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PRC: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

function roundUp(n: number): number {
  const t = Math.round(n * 100000);
  if (t % 10000 === 0) return t / 100000;
  return Math.ceil(n * 10) / 10;
}

export function cvssBaseFromVector(vector: string): number | undefined {
  const m = vector.match(
    /AV:([NALP]).*AC:([LH]).*PR:([NLH]).*UI:([NR]).*S:([UC]).*C:([NLH]).*I:([NLH]).*A:([NLH])/,
  );
  if (!m) {
    const num = vector.match(/(\d+\.\d+)/);
    return num ? Number(num[1]) : undefined;
  }
  const [, av, ac, pr, ui, s, c, i, a] = m;
  const iss = 1 - (1 - (CIA[c!] ?? 0)) * (1 - (CIA[i!] ?? 0)) * (1 - (CIA[a!] ?? 0));
  const impact =
    s === "U"
      ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const exploit = 8.22 * (AV[av!] ?? 0) * (AC[ac!] ?? 0) * ((s === "C" ? PRC : PRU)[pr!] ?? 0) * (UI[ui!] ?? 0);
  if (impact <= 0) return 0;
  const base = s === "U" ? Math.min(impact + exploit, 10) : Math.min(1.08 * (impact + exploit), 10);
  return roundUp(base);
}

export function severityFromScore(score: number | undefined, fallback?: string): import("./types").Severity {
  const label = (fallback ?? "").toUpperCase();
  if (label.includes("CRIT")) return "critical";
  if (label === "HIGH") return "high";
  if (label === "MODERATE" || label === "MEDIUM") return "medium";
  if (label === "LOW") return "low";
  if (score == null) return "medium";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}
