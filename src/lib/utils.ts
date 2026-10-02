import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function uid(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  return `s_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

export function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

export function downloadFile(filename: string, contents: string, mime: string) {
  const blob = new Blob([contents], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export async function mapPool<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]!, i);
    }
  });
  await Promise.all(workers);
  return results;
}

export function stripRange(raw: string): string | null {
  const v = raw.trim().replace(/^['"]|['"]$/g, "");
  if (!v || v === "*" || v === "latest" || v === "workspace:*") return null;
  if (v.startsWith("file:") || v.startsWith("link:") || v.startsWith("git+") || v.startsWith("github:")) {
    return null;
  }
  const cleaned = v
    .replace(/^(workspace:)/, "")
    .replace(/^npm:/, "")
    .replace(/^[~^>=<\s]+/, "")
    .replace(/\s+\|\|.*$/, "")
    .replace(/\s+$/, "");
  const m = cleaned.match(/^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)/);
  if (m) return m[1]!;
  const loose = cleaned.match(/^v?(\d+\.\d+(?:\.\d+)?)/);
  return loose ? loose[1]! : null;
}

export function compareSemver(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(/[+-]/)[0]!.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.replace(/^v/, "").split(/[+-]/)[0]!.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da > db) return 1;
    if (da < db) return -1;
  }
  return 0;
}

export function formatWhen(iso: string): string {
  try {
    return new Intl.DateTimeFormat("pt-BR", {
      dateStyle: "short",
      timeStyle: "short",
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}
