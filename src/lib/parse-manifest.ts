import { purlFor } from "./osv";
import type { DepScope, Ecosystem, ScannedPackage } from "./types";
import { stripRange } from "./utils";

export interface ProjectFile {
  path: string;
  content: string;
}

export interface ParseResult {
  title: string;
  packages: ScannedPackage[];
  notes: string[];
  kind: "manifest" | "project" | "mixed";
}

const SKIP_DIR = /(^|\/)(node_modules|\.git|dist|build|coverage|\.next|vendor|__pycache__|\.venv|target)(\/|$)/;

export function shouldSkipPath(path: string): boolean {
  return SKIP_DIR.test(path.replaceAll("\\", "/"));
}

export function parseProjectFiles(files: ProjectFile[]): ParseResult {
  const packages: ScannedPackage[] = [];
  const notes: string[] = [];
  let title = "projeto";
  const names: string[] = [];

  const byName = new Map(files.map((f) => [normalizePath(f.path), f]));
  const pkgJson = firstMatch(byName, /(^|\/)package\.json$/);
  const lock =
    firstMatch(byName, /(^|\/)package-lock\.json$/) ||
    firstMatch(byName, /(^|\/)yarn\.lock$/) ||
    firstMatch(byName, /(^|\/)pnpm-lock\.yaml$/);

  if (pkgJson) {
    const parsed = parsePackageJson(pkgJson.content, lock?.content, lock?.path);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
    names.push(parsed.title);
  } else if (lock) {
    const parsed = parseNpmLockOnly(lock.content, lock.path);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
  }

  const req = firstMatch(byName, /(^|\/)requirements\.txt$/) || firstMatch(byName, /(^|\/)pyproject\.toml$/);
  if (req) {
    const parsed = req.path.endsWith(".toml") ? parsePyproject(req.content) : parseRequirements(req.content);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
    names.push(parsed.title);
  }

  const gomod = firstMatch(byName, /(^|\/)go\.mod$/);
  if (gomod) {
    const parsed = parseGoMod(gomod.content);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
    names.push(parsed.title);
  }

  const cargo = firstMatch(byName, /(^|\/)Cargo\.lock$/) || firstMatch(byName, /(^|\/)Cargo\.toml$/);
  if (cargo) {
    const parsed = cargo.path.endsWith(".lock") ? parseCargoLock(cargo.content) : parseCargoToml(cargo.content);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
    names.push(parsed.title);
  }

  const composer = firstMatch(byName, /(^|\/)composer\.lock$/) || firstMatch(byName, /(^|\/)composer\.json$/);
  if (composer) {
    const parsed = composer.path.endsWith(".lock")
      ? parseComposerLock(composer.content)
      : parseComposerJson(composer.content);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
    names.push(parsed.title);
  }

  const gem = firstMatch(byName, /(^|\/)Gemfile\.lock$/);
  if (gem) {
    const parsed = parseGemfileLock(gem.content);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
  }

  const pom = firstMatch(byName, /(^|\/)pom\.xml$/);
  if (pom) {
    const parsed = parsePom(pom.content);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
  }

  const pubspec = firstMatch(byName, /(^|\/)pubspec\.yaml$/);
  if (pubspec) {
    const parsed = parsePubspec(pubspec.content);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
  }

  const poetry = firstMatch(byName, /(^|\/)poetry\.lock$/);
  if (poetry) {
    const parsed = parsePoetryLock(poetry.content);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
  }

  const pipfile = firstMatch(byName, /(^|\/)Pipfile\.lock$/) || firstMatch(byName, /(^|\/)Pipfile$/);
  if (pipfile) {
    const parsed = pipfile.path.endsWith(".lock") ? parsePipfileLock(pipfile.content) : parsePipfile(pipfile.content);
    packages.push(...parsed.packages);
    notes.push(...parsed.notes);
  }

  for (const file of files) {
    if (!/(^|\/)\.github\/workflows\/.+\.ya?ml$/.test(normalizePath(file.path))) continue;
    packages.push(...parseGithubActions(file.content));
  }

  if (names[0]) title = names[0];
  const unique = dedupePackages(packages);
  return {
    title,
    packages: unique,
    notes,
    kind: files.length > 1 ? "project" : "manifest",
  };
}

export function parseLooseText(filename: string, text: string): ParseResult {
  const path = filename || guessFilename(text);
  return parseProjectFiles([{ path, content: text }]);
}

function guessFilename(text: string): string {
  const t = text.trim();
  if (t.startsWith("{") && t.includes('"dependencies"')) return "package.json";
  if (t.startsWith("{") && t.includes('"packages"') && t.includes("node_modules")) return "package-lock.json";
  if (t.includes("lockfileVersion") && t.includes("packages:")) return "pnpm-lock.yaml";
  if (/^[\w.-]+==/.test(t) || /Django|Flask|requests/.test(t)) return "requirements.txt";
  if (t.startsWith("module ") || t.includes("\nrequire (")) return "go.mod";
  if (t.includes("[dependencies]") && t.includes("version")) return "Cargo.toml";
  if (t.includes('"require"') && t.includes("vendor")) return "composer.json";
  if (t.includes("GEM") && t.includes("specs:")) return "Gemfile.lock";
  if (t.includes("<project") && t.includes("<artifactId>")) return "pom.xml";
  if (t.startsWith("{")) return "package.json";
  return "requirements.txt";
}

function parsePackageJson(raw: string, lockRaw?: string, lockPath?: string): ParseResult {
  const json = jsonish(raw) as {
    name?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
    licenses?: unknown;
    license?: string | { type?: string };
  };
  const declared = new Map<string, ScannedPackage>();
  const add = (deps: Record<string, string> | undefined, scope: DepScope) => {
    if (!deps) return;
    for (const [name, range] of Object.entries(deps)) {
      const version = stripRange(range);
      declared.set(`${name}:${scope}`, pkg("npm", name, version, scope, version ? undefined : true, licenseOf(json)));
    }
  };
  add(json.dependencies, "direct");
  add(json.devDependencies, "dev");
  add(json.optionalDependencies, "optional");
  add(json.peerDependencies, "peer");

  const notes: string[] = [];
  if (lockRaw) {
    const locked = parseNpmLockOnly(lockRaw, lockPath ?? "lock").packages;
    const merged = new Map<string, ScannedPackage>();
    for (const p of locked) {
      const d = [...declared.values()].find((x) => x.name === p.name);
      merged.set(p.name, {
        ...p,
        scope: d?.scope ?? "transitive",
        license: d?.license ?? p.license,
      });
    }
    for (const p of declared.values()) {
      if (!merged.has(p.name) && p.version) merged.set(p.name, p);
      else if (!merged.has(p.name)) notes.push(`${p.name} sem versão pinada e ausente no lockfile.`);
    }
    return { title: json.name || "package.json", packages: [...merged.values()], notes, kind: "manifest" };
  }

  notes.push("Lockfile ausente — OSV usa a versão declarada (sem transitivas).");
  return { title: json.name || "package.json", packages: [...declared.values()], notes, kind: "manifest" };
}

function parseNpmLockOnly(raw: string, path: string): ParseResult {
  if (path.endsWith("yarn.lock") || raw.includes("yarn lockfile")) return parseYarnLock(raw);
  if (path.endsWith("pnpm-lock.yaml") || raw.includes("lockfileVersion:")) return parsePnpmLock(raw);
  const json = jsonish(raw) as {
    name?: string;
    dependencies?: Record<string, { version?: string }>;
    packages?: Record<string, { version?: string; dev?: boolean; optional?: boolean; license?: string }>;
  };
  const packages: ScannedPackage[] = [];
  if (json.packages) {
    for (const [key, meta] of Object.entries(json.packages)) {
      if (!key || key === "") continue;
      const name = npmNameFromPath(key);
      if (!name || !meta.version) continue;
      const scope: DepScope = meta.dev ? "dev" : meta.optional ? "optional" : key.split("node_modules/").length > 2 ? "transitive" : "direct";
      packages.push(pkg("npm", name, meta.version, scope, false, meta.license));
    }
  } else if (json.dependencies) {
    for (const [name, meta] of Object.entries(json.dependencies)) {
      if (meta.version) packages.push(pkg("npm", name, meta.version, "direct"));
    }
  }
  return { title: json.name || "package-lock.json", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parseYarnLock(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const re = /^(?:"?(@?[^@\s:"]+(?:\/[^@\s:"]+)?).*?|"?[^"\n]+"):\n(?: {2}.*\n)*? {2}version "?([^"\n]+)"?/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    const key = m[1] ?? "";
    const name = key.replace(/^"+|"+$/g, "").split("@npm:")[0]!.split("@")[0] || key;
    const cleaned = name.startsWith("@") ? `@${name.split("@")[1] ?? name}` : name.split("@")[0]!;
    packages.push(pkg("npm", cleaned.includes("/") && !cleaned.startsWith("@") ? m[1]!.split("@")[0]! : guessYarnName(m[0]!), m[2]!, "transitive"));
  }
  // Fallback simpler parser
  if (packages.length === 0) {
    const blocks = raw.split(/\n\n+/);
    for (const block of blocks) {
      const header = block.split("\n")[0] ?? "";
      const ver = block.match(/version "?([^"\n]+)"/)?.[1];
      const name = yarnKeyName(header);
      if (name && ver) packages.push(pkg("npm", name, ver, "transitive"));
    }
  }
  return { title: "yarn.lock", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function yarnKeyName(header: string): string | null {
  const h = header.replace(/:$/, "").replaceAll('"', "").split(",")[0]!.trim();
  if (!h) return null;
  if (h.startsWith("@")) {
    const parts = h.split("@");
    return `@${parts[1]}`;
  }
  return h.split("@")[0] || null;
}

function guessYarnName(block: string): string {
  return yarnKeyName(block.split("\n")[0] ?? "") ?? "unknown";
}

function parsePnpmLock(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const re = /^\s{2}['"]?(?:\/)?(@?[\w.-]+(?:\/[\w.-]+)?)[@/](\d[^'"(\s]*)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    packages.push(pkg("npm", m[1]!, m[2]!.replace(/:.+$/, ""), "transitive"));
  }
  return { title: "pnpm-lock.yaml", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parseRequirements(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#") || t.startsWith("-")) continue;
    const cleaned = t.split("#")[0]!.trim().replace(/\[.*\]/, "");
    const m = cleaned.match(/^([A-Za-z0-9_.-]+)\s*([=<>!~]+)?\s*([^\\s;]+)?/);
    if (!m) continue;
    const version = m[3] ? stripRange(m[2] ? `${m[2]}${m[3]}` : m[3]) : null;
    packages.push(pkg("PyPI", m[1]!, version, "direct", !version));
  }
  return { title: "requirements.txt", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parsePyproject(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const block = raw.match(/\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
  const list = block?.[1] ?? "";
  for (const item of list.split(",")) {
    const s = item.replaceAll('"', "").replaceAll("'", "").trim();
    if (!s) continue;
    const m = s.match(/^([A-Za-z0-9_.-]+)\s*([=<>!~].+)?$/);
    if (!m) continue;
    packages.push(pkg("PyPI", m[1]!, m[2] ? stripRange(m[2]) : null, "direct", !m[2]));
  }
  return { title: "pyproject.toml", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parseGoMod(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const module = raw.match(/^module\s+(\S+)/m)?.[1] ?? "go.mod";
  const re = /^\s*([^\s]+)\s+v([0-9][^\s]+)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    if (m[1] === "module" || m[1] === "go") continue;
    packages.push(pkg("Go", m[1]!, m[2]!, "direct"));
  }
  return { title: module, packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parseCargoToml(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const block = raw.split(/\[dependencies\]/)[1]?.split(/\n\[/)[0] ?? "";
  for (const line of block.split(/\n/)) {
    const m = line.match(/^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/);
    if (m) packages.push(pkg("crates.io", m[1]!, stripRange(m[2]!), "direct"));
  }
  return { title: "Cargo.toml", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parseCargoLock(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const blocks = raw.split(/\[\[package\]\]/).slice(1);
  for (const b of blocks) {
    const name = b.match(/name\s*=\s*"([^"]+)"/)?.[1];
    const version = b.match(/version\s*=\s*"([^"]+)"/)?.[1];
    if (name && version) packages.push(pkg("crates.io", name, version, "transitive"));
  }
  return { title: "Cargo.lock", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parseComposerJson(raw: string): ParseResult {
  const json = jsonish(raw) as { name?: string; require?: Record<string, string> };
  const packages: ScannedPackage[] = [];
  for (const [name, range] of Object.entries(json.require ?? {})) {
    if (name === "php") continue;
    packages.push(pkg("Packagist", name, stripRange(range), "direct", !stripRange(range)));
  }
  return { title: json.name || "composer.json", packages, notes: [], kind: "manifest" };
}

function parseComposerLock(raw: string): ParseResult {
  const json = jsonish(raw) as { packages?: { name: string; version: string }[] };
  const packages = (json.packages ?? []).map((p) => pkg("Packagist", p.name, p.version.replace(/^v/, ""), "direct"));
  return { title: "composer.lock", packages, notes: [], kind: "manifest" };
}

function parseGemfileLock(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const re = /^\s{4}([a-z0-9_-]+) \(([^)]+)\)/gim;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) packages.push(pkg("RubyGems", m[1]!, m[2]!, "transitive"));
  return { title: "Gemfile.lock", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parsePom(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const re =
    /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?(?:<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    const name = `${m[1]!.trim()}:${m[2]!.trim()}`;
    const version = m[3]?.trim() && !m[3].includes("$") ? m[3].trim() : null;
    packages.push(pkg("Maven", name, version, "direct", !version));
  }
  return { title: "pom.xml", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parsePubspec(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const block = raw.split(/dependencies:\s*\n/)[1]?.split(/\n[a-z]/)[0] ?? "";
  for (const line of block.split("\n")) {
    const m = line.match(/^\s{2}([a-z0-9_]+):\s*(\S+)?/i);
    if (m && m[1] !== "flutter" && m[1] !== "sdk") {
      packages.push(pkg("Pub", m[1]!, m[2] ? stripRange(m[2]) : null, "direct", !m[2]));
    }
  }
  return { title: "pubspec.yaml", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parseGithubActions(raw: string): ScannedPackage[] {
  const packages: ScannedPackage[] = [];
  const re = /uses:\s*([^\s@]+)@([^\s]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    const name = m[1]!.replace(/^\.+\//, "");
    if (name.startsWith("docker://")) continue;
    packages.push(pkg("GitHub Actions", name, m[2]!.replace(/^v/, ""), "direct"));
  }
  return packages;
}

function parsePoetryLock(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const blocks = raw.split(/\[\[package\]\]/).slice(1);
  for (const b of blocks) {
    const name = b.match(/name\s*=\s*"([^"]+)"/)?.[1];
    const version = b.match(/version\s*=\s*"([^"]+)"/)?.[1];
    if (name && version) packages.push(pkg("PyPI", name, version, "transitive"));
  }
  return { title: "poetry.lock", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parsePipfileLock(raw: string): ParseResult {
  const json = jsonish(raw) as { default?: Record<string, { version?: string }>; develop?: Record<string, { version?: string }> };
  const packages: ScannedPackage[] = [];
  const add = (bag: Record<string, { version?: string }> | undefined, scope: DepScope) => {
    if (!bag) return;
    for (const [name, meta] of Object.entries(bag)) {
      const version = meta.version ? stripRange(meta.version) : null;
      packages.push(pkg("PyPI", name, version, scope, !version));
    }
  };
  add(json.default, "direct");
  add(json.develop, "dev");
  return { title: "Pipfile.lock", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function parsePipfile(raw: string): ParseResult {
  const packages: ScannedPackage[] = [];
  const block = raw.split(/\[packages\]/)[1]?.split(/\n\[/)[0] ?? "";
  for (const line of block.split("\n")) {
    const m = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*"([^"]+)"/);
    if (m) packages.push(pkg("PyPI", m[1]!, stripRange(m[2]!), "direct", !stripRange(m[2]!)));
  }
  return { title: "Pipfile", packages: dedupePackages(packages), notes: [], kind: "manifest" };
}

function pkg(
  ecosystem: Ecosystem,
  name: string,
  version: string | null,
  scope: DepScope,
  unpinned?: boolean,
  license?: string,
): ScannedPackage {
  return {
    name,
    version,
    ecosystem,
    scope,
    unpinned,
    license,
    purl: purlFor(ecosystem, name, version),
  };
}

function licenseOf(json: { license?: string | { type?: string } }): string | undefined {
  if (typeof json.license === "string") return json.license;
  if (json.license && typeof json.license === "object") return json.license.type;
  return undefined;
}

function npmNameFromPath(key: string): string | null {
  const idx = key.lastIndexOf("node_modules/");
  if (idx === -1) return key || null;
  const rest = key.slice(idx + "node_modules/".length);
  return rest || null;
}

function dedupePackages(packages: ScannedPackage[]): ScannedPackage[] {
  const map = new Map<string, ScannedPackage>();
  for (const p of packages) {
    const k = `${p.ecosystem}:${p.name}@${p.version ?? ""}`;
    const prev = map.get(k);
    if (!prev) map.set(k, p);
    else if (prev.scope === "transitive" && p.scope !== "transitive") map.set(k, p);
  }
  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function firstMatch(files: Map<string, ProjectFile>, re: RegExp): ProjectFile | undefined {
  for (const [path, file] of files) {
    if (re.test(path)) return file;
  }
  return undefined;
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

function jsonish(raw: string): Record<string, unknown> {
  const stripped = raw.replace(/^\uFEFF/, "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  return JSON.parse(stripped) as Record<string, unknown>;
}
