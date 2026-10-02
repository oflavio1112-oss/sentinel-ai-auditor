import { shouldSkipPath, type ProjectFile } from "./parse-manifest";
import { mapPool } from "./utils";

const MANIFESTS = [
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "requirements.txt",
  "pyproject.toml",
  "poetry.lock",
  "Pipfile.lock",
  "Pipfile",
  "go.mod",
  "go.sum",
  "Cargo.lock",
  "Cargo.toml",
  "composer.lock",
  "composer.json",
  "Gemfile.lock",
  "Gemfile",
  "pom.xml",
  "build.gradle",
  "pubspec.yaml",
];

const INTERESTING =
  /(^|\/)(Dockerfile|docker-compose\.ya?ml|\.env|\.env\.[^/]+|\.npmrc|Procfile)$/i;

const WORKFLOW = /(^|\/)\.github\/workflows\/.+\.ya?ml$/i;
const CODE = /\.(js|jsx|ts|tsx|mjs|cjs|py|go|rb|php|java|cs|rs|vue)$/i;

export function parseGithub(url: string): { owner: string; repo: string; branch?: string } | null {
  try {
    const u = new URL(url.trim());
    if (!/github\.com$/i.test(u.hostname)) return null;
    const parts = u.pathname.replace(/^\//, "").replace(/\.git$/, "").split("/");
    if (parts.length < 2 || !parts[0] || !parts[1]) return null;
    const branch = parts[2] === "tree" ? parts.slice(3).join("/") : undefined;
    return { owner: parts[0], repo: parts[1], branch };
  } catch {
    return null;
  }
}

export async function fetchGithubFiles(url: string): Promise<{
  title: string;
  files: ProjectFile[];
  notes: string[];
}> {
  const parsed = parseGithub(url);
  if (!parsed) throw new Error("URL do GitHub inválida. Use https://github.com/org/repo");
  const title = `${parsed.owner}/${parsed.repo}`;
  const notes: string[] = [];
  const branch = parsed.branch || (await detectBranch(parsed.owner, parsed.repo));
  const tree = await fetchTree(parsed.owner, parsed.repo, branch);
  const selected = tree.length ? pickPaths(tree) : MANIFESTS;
  if (tree.length) notes.push(`GitHub: ${tree.length} arquivos no tree, ${selected.length} selecionados (${branch}).`);
  const files = await mapPool(selected, 8, async (path) => {
    const content = await fetchRaw(parsed.owner, parsed.repo, branch, path);
    return content ? ({ path, content } satisfies ProjectFile) : null;
  });
  const kept = files.filter((f): f is ProjectFile => Boolean(f));
  if (kept.length === 0) {
    throw new Error("Não encontrei manifestos públicos (package.json, requirements.txt, go.mod…).");
  }
  return { title, files: kept, notes };
}

async function detectBranch(owner: string, repo: string): Promise<string> {
  try {
    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (res.ok) {
      const body = (await res.json()) as { default_branch?: string };
      if (body.default_branch) return body.default_branch;
    }
  } catch {
    /* ignore */
  }
  return "HEAD";
}

async function fetchTree(owner: string, repo: string, branch: string): Promise<string[]> {
  const urls = [
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    `https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`,
  ];
  for (const url of urls) {
    try {
      const res = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
      if (!res.ok) continue;
      const body = (await res.json()) as { tree?: { path?: string; type?: string; size?: number }[] };
      return (body.tree ?? [])
        .filter((n) => n.type === "blob" && n.path && (n.size ?? 0) < 750_000)
        .map((n) => n.path!)
        .filter((p) => !shouldSkipPath(p));
    } catch {
      /* try next */
    }
  }
  return [];
}

function pickPaths(tree: string[]): string[] {
  const manifests = tree.filter((p) => MANIFESTS.some((m) => p === m || p.endsWith(`/${m}`)));
  const extra = tree.filter((p) => INTERESTING.test(p) || WORKFLOW.test(p));
  const code = tree.filter((p) => CODE.test(p) && !p.includes("test") && !p.includes("__")).slice(0, 40);
  return [...new Set([...manifests, ...extra, ...code])].slice(0, 90);
}

export async function fetchRaw(owner: string, repo: string, branch: string, path: string): Promise<string | null> {
  const urls = [
    `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`,
    `https://cdn.jsdelivr.net/gh/${owner}/${repo}@${branch}/${path}`,
  ];
  for (const url of urls) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.text();
    } catch {
      /* try next */
    }
  }
  return null;
}
