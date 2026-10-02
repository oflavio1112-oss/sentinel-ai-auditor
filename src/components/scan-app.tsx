import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Box,
  Check,
  Cloud,
  CloudOff,
  Copy,
  FileCode2,
  FolderArchive,
  Github,
  Loader2,
  Radar,
  Shield,
  Sparkles,
} from "lucide-react";
import { toast } from "sonner";
import { briefScan } from "@/lib/ai";
import {
  loadFullReport,
  loadHistory,
  loadLocalHistory,
  persistScan,
  SCANS_DDL,
  type CloudStatus,
} from "@/lib/supabase";
import { toCycloneDx, toMarkdown, toSarif } from "@/lib/report";
import { SAMPLE_CODE, SAMPLE_PACKAGE_JSON, SAMPLE_REQUIREMENTS } from "@/lib/samples";
import { scanGithubRepo, scanText, scanZip } from "@/lib/scan-engine";
import type { Finding, ScanReport, ScanStats, ScanSummary, Severity } from "@/lib/types";
import { emptyStats } from "@/lib/types";
import { downloadFile, formatWhen } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";

type TabKey = "manifest" | "code" | "zip" | "github";
type FilterKey = "all" | Severity | "vuln" | "secret" | "sast" | "hygiene";

const SEV_TONE: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

export function ScanApp() {
  const [tab, setTab] = useState<TabKey>("manifest");
  const [manifest, setManifest] = useState(SAMPLE_PACKAGE_JSON);
  const [code, setCode] = useState(SAMPLE_CODE);
  const [github, setGithub] = useState("https://github.com/lodash/lodash");
  const [filename, setFilename] = useState("package.json");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [filter, setFilter] = useState<FilterKey>("all");
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [cloud, setCloud] = useState<CloudStatus>("offline");
  const [aiBusy, setAiBusy] = useState(false);
  const [copiedSql, setCopiedSql] = useState(false);
  const zipRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setHistory(loadLocalHistory());
    void loadHistory().then((loaded) => {
      setCloud(loaded.cloud);
      setHistory(loaded.rows);
    });
  }, []);

  const visible = useMemo(() => {
    if (!report) return [];
    return report.findings.filter((f) => {
      if (filter === "all") return true;
      if (filter === "vuln") return f.kind === "vuln" || f.kind === "malware";
      if (filter === "secret" || filter === "sast" || filter === "hygiene") return f.kind === filter;
      return f.severity === filter;
    });
  }, [report, filter]);

  async function runWith(fn: () => Promise<ScanReport>) {
    setBusy(true);
    setProgress("Consultando OSV.dev, npm registry e analisando o alvo…");
    try {
      const next = await fn();
      setReport(next);
      setFilter("all");
      setProgress("");
      const saved = await persistScan(next);
      setCloud(saved.cloud);
      setHistory((prev) => [saved.summary, ...prev.filter((r) => r.id !== saved.summary.id)].slice(0, 40));
      toast.success(`Scan concluído — risco ${next.riskScore}/100`);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Falha no scan.";
      toast.error(message);
      setProgress("");
    } finally {
      setBusy(false);
    }
  }

  function onZip(file: File | undefined) {
    if (!file) return;
    if (file.name.endsWith(".zip") || file.type === "application/zip") {
      void runWith(async () => {
        const buf = await file.arrayBuffer();
        return scanZip(buf, file.name);
      });
      return;
    }
    void runWith(async () => {
      const text = await file.text();
      setFilename(file.name);
      setManifest(text);
      setTab("manifest");
      return scanText(file.name, text);
    });
  }

  function openHistory(row: ScanSummary) {
    const full = loadFullReport(row.id);
    if (full) {
      setReport(full);
      return;
    }
    if (!row.top?.length) {
      toast.message("Este item só tem resumo. Rode o scan de novo para o relatório completo.");
      return;
    }
    const stats = emptyStats();
    stats.packages = row.packageCount;
    stats.findings = row.findingCount;
    stats.critical = row.criticalCount;
    stats.high = row.highCount;
    stats.medium = row.mediumCount;
    stats.low = row.lowCount;
    setReport({
      id: row.id,
      createdAt: row.createdAt,
      title: row.title,
      sourceKind: row.sourceKind,
      packages: [],
      findings: row.top.map((f) => ({
        id: f.id,
        kind: f.kind,
        severity: f.severity,
        title: f.title,
        description: f.title,
        packageName: f.packageName,
        osvId: f.osvId,
        fixedVersion: f.fixedVersion,
      })),
      stats,
      riskScore: row.riskScore,
      notes: ["Relatório resumido do histórico (nuvem/local)."],
      durationMs: 0,
    });
  }

  async function askAi() {
    if (!report) return;
    setAiBusy(true);
    try {
      const res = await briefScan({
        data: {
          title: report.title,
          riskScore: report.riskScore,
          stats: report.stats,
          findings: report.findings.slice(0, 16).map((f) => ({
            severity: f.severity,
            kind: f.kind,
            title: f.title,
            packageName: f.packageName,
            osvId: f.osvId,
            fixedVersion: f.fixedVersion,
          })),
        },
      });
      if (!res.ok) {
        toast.error(res.error);
        return;
      }
      setReport({ ...report, aiBrief: res.text });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "IA indisponível.");
    } finally {
      setAiBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-bg text-fg">
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <span className="flex size-11 items-center justify-center rounded-lg border border-border bg-surface">
              <Shield className="size-5 text-accent" strokeWidth={1.6} />
            </span>
            <div>
              <p className="font-display text-lg font-medium tracking-tight">Sentinel AI</p>
              <p className="text-xs text-muted">Auditor de código e dependências · OSV.dev</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <CloudBadge status={cloud} />
            {report ? (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downloadFile(`sentinel-${report.title}.md`, toMarkdown(report), "text/markdown")}
                >
                  Markdown
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downloadFile(`sentinel-${report.title}.sarif.json`, toSarif(report), "application/json")}
                >
                  SARIF
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downloadFile(`sentinel-${report.title}.cdx.json`, toCycloneDx(report), "application/json")}
                >
                  SBOM
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    downloadFile(`sentinel-${report.title}.json`, JSON.stringify(report, null, 2), "application/json")
                  }
                >
                  JSON
                </Button>
              </>
            ) : null}
          </div>
        </div>
      </header>

      <main className="mx-auto grid max-w-7xl gap-6 px-4 py-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="flex flex-col gap-6">
          <Card>
            <CardHeader>
              <CardTitle>Alvo</CardTitle>
              <p className="text-sm text-muted">
                Cole um manifesto, código, ZIP ou URL pública do GitHub. O scan chama a API real do OSV.dev e cruza
                com SAST, Docker, typosquat e latest do npm.
              </p>
            </CardHeader>
            <CardContent>
              <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
                <TabsList className="flex h-auto w-full flex-wrap justify-start">
                  <TabsTrigger value="manifest">Dependências</TabsTrigger>
                  <TabsTrigger value="code">Código</TabsTrigger>
                  <TabsTrigger value="zip">ZIP</TabsTrigger>
                  <TabsTrigger value="github">GitHub</TabsTrigger>
                </TabsList>
                <TabsContent value="manifest" className="flex flex-col gap-3">
                  <Textarea value={manifest} onChange={(e) => setManifest(e.target.value)} spellCheck={false} className="min-h-52" />
                  <div className="flex flex-wrap gap-2">
                    <Button disabled={busy} onClick={() => void runWith(() => scanText(filename, manifest))}>
                      {busy ? <Loader2 className="animate-spin" /> : <Radar />} Escanear manifesto
                    </Button>
                    <Button
                      variant="secondary"
                      disabled={busy}
                      data-testid="demo-npm"
                      onClick={() => {
                        setManifest(SAMPLE_PACKAGE_JSON);
                        setFilename("package.json");
                        void runWith(() => scanText("package.json", SAMPLE_PACKAGE_JSON));
                      }}
                    >
                      Demo npm vulnerável
                    </Button>
                    <Button
                      variant="secondary"
                      disabled={busy}
                      onClick={() => {
                        setManifest(SAMPLE_REQUIREMENTS);
                        setFilename("requirements.txt");
                        void runWith(() => scanText("requirements.txt", SAMPLE_REQUIREMENTS));
                      }}
                    >
                      Demo PyPI
                    </Button>
                  </div>
                </TabsContent>
                <TabsContent value="code" className="flex flex-col gap-3">
                  <Textarea value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} className="min-h-52" />
                  <Button disabled={busy} onClick={() => void runWith(() => scanText("app.js", code))}>
                    {busy ? <Loader2 className="animate-spin" /> : <FileCode2 />} Auditar código
                  </Button>
                </TabsContent>
                <TabsContent value="zip" className="flex flex-col gap-3">
                  <input
                    ref={zipRef}
                    type="file"
                    accept=".zip,.json,.txt,.toml,.mod,.lock,.xml,.yml,.yaml"
                    className="hidden"
                    onChange={(e) => onZip(e.target.files?.[0])}
                  />
                  <button
                    type="button"
                    onClick={() => zipRef.current?.click()}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      onZip(e.dataTransfer.files?.[0]);
                    }}
                    className="flex min-h-40 flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-bg px-4 text-sm text-muted transition-colors duration-150 hover:text-fg"
                  >
                    <FolderArchive className="size-6" />
                    Envie um .zip do projeto (sem node_modules) ou um manifesto
                  </button>
                </TabsContent>
                <TabsContent value="github" className="flex flex-col gap-3">
                  <Input value={github} onChange={(e) => setGithub(e.target.value)} placeholder="https://github.com/org/repo" />
                  <Button disabled={busy} onClick={() => void runWith(() => scanGithubRepo(github))}>
                    {busy ? <Loader2 className="animate-spin" /> : <Github />} Escanear repositório público
                  </Button>
                </TabsContent>
              </Tabs>
              {busy ? <p className="mt-3 text-xs text-muted">{progress}</p> : null}
            </CardContent>
          </Card>

          {report ? (
            <ReportPanel report={report} filter={filter} setFilter={setFilter} visible={visible} aiBusy={aiBusy} onAi={() => void askAi()} />
          ) : (
            <EmptyState />
          )}
        </div>

        <aside className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Supabase</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3 text-sm text-muted">
              <CloudBadge status={cloud} />
              {cloud === "missing-table" ? (
                <>
                  <p>
                    Projeto ligado, falta criar a tabela <span className="font-mono text-fg">scans</span> no SQL Editor.
                  </p>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={async () => {
                      await navigator.clipboard.writeText(SCANS_DDL);
                      setCopiedSql(true);
                      toast.message("SQL copiado");
                    }}
                  >
                    {copiedSql ? <Check /> : <Copy />} Copiar DDL
                  </Button>
                </>
              ) : cloud === "ok" ? (
                <p>Histórico gravado no projeto pewhzyjibtfnnvevizpm (sem trechos de segredo).</p>
              ) : (
                <p>O histórico fica neste navegador. A nuvem liga depois do primeiro scan, se a tabela scans existir.</p>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  const loaded = await loadHistory();
                  setCloud(loaded.cloud);
                  setHistory(loaded.rows);
                  toast.message(loaded.cloud === "ok" ? "Histórico sincronizado" : "Usando histórico local");
                }}
              >
                Sincronizar nuvem
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Histórico</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              {history.length === 0 ? (
                <p className="text-sm text-muted">Nenhum scan ainda.</p>
              ) : (
                history.slice(0, 12).map((row) => (
                  <button
                    key={row.id}
                    type="button"
                    onClick={() => openHistory(row)}
                    className="rounded-lg border border-border bg-bg px-3 py-2 text-left transition-colors duration-150 hover:bg-surface-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className="truncate text-sm text-fg">{row.title}</p>
                      <span className="font-mono text-xs tabular-nums text-muted">{row.riskScore}</span>
                    </div>
                    <p className="text-xs text-subtle">
                      {formatWhen(row.createdAt)} · {row.findingCount} achados
                      {row.remote ? " · nuvem" : ""}
                    </p>
                  </button>
                ))
              )}
            </CardContent>
          </Card>
        </aside>
      </main>
    </div>
  );
}

function ReportPanel({
  report,
  filter,
  setFilter,
  visible,
  aiBusy,
  onAi,
}: {
  report: ScanReport;
  filter: FilterKey;
  setFilter: (v: FilterKey) => void;
  visible: Finding[];
  aiBusy: boolean;
  onAi: () => void;
}) {
  return (
    <Card>
      <CardHeader className="gap-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-[0.14em] text-subtle">Relatório</p>
            <CardTitle className="font-display text-xl">{report.title}</CardTitle>
            <p className="text-xs text-muted">
              {report.stats.packages} pacotes · {report.durationMs} ms · {report.sourceKind}
            </p>
          </div>
          <RiskMeter score={report.riskScore} />
        </div>
        <SeverityBar stats={report.stats} />
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat label="Crítico" value={report.stats.critical} tone="critical" />
          <Stat label="Alto" value={report.stats.high} tone="high" />
          <Stat label="Médio" value={report.stats.medium} tone="medium" />
          <Stat label="Segredos" value={report.stats.secrets} tone="critical" />
        </div>
        <div className="flex flex-wrap gap-2">
          {(["all", "critical", "high", "medium", "vuln", "secret", "sast", "hygiene"] as const).map((key) => (
            <Button key={key} size="sm" variant={filter === key ? "default" : "secondary"} onClick={() => setFilter(key)}>
              {labelFilter(key)}
            </Button>
          ))}
          <Button size="sm" variant="outline" disabled={aiBusy} onClick={onAi}>
            {aiBusy ? <Loader2 className="animate-spin" /> : <Sparkles />} Briefing IA
          </Button>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {report.aiBrief ? (
          <div className="rounded-lg border border-border bg-bg p-4 text-sm leading-relaxed whitespace-pre-wrap text-muted">
            {report.aiBrief}
          </div>
        ) : null}
        {report.notes.length ? (
          <ul className="space-y-1 text-xs text-subtle">
            {report.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        ) : null}
        <Separator />
        {visible.length === 0 ? (
          <p className="text-sm text-muted">Nenhum achado neste filtro.</p>
        ) : (
          <ul className="flex flex-col gap-3">
            {visible.map((f) => (
              <li key={f.id} className="rounded-lg border border-border bg-bg p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={SEV_TONE[f.severity]}>{f.severity}</Badge>
                  <Badge>{f.kind}</Badge>
                  {f.malicious ? <Badge tone="critical">malware</Badge> : null}
                  <p className="text-sm font-medium">{f.title}</p>
                </div>
                <p className="mt-2 text-sm text-muted">{f.description}</p>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-subtle">
                  {f.packageName ? (
                    <span>
                      {f.packageName}
                      {f.packageVersion ? `@${f.packageVersion}` : ""}
                    </span>
                  ) : null}
                  {f.osvId ? (
                    <a
                      className="underline decoration-border underline-offset-2 hover:text-fg"
                      href={`https://osv.dev/vulnerability/${f.osvId}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {f.osvId}
                    </a>
                  ) : null}
                  {f.cvss != null ? <span>CVSS {f.cvss}</span> : null}
                  {f.fixedVersion ? <span>fix {f.fixedVersion}</span> : null}
                  {f.file ? (
                    <span>
                      {f.file}
                      {f.line ? `:${f.line}` : ""}
                    </span>
                  ) : null}
                </div>
                {f.snippet ? (
                  <pre className="mt-2 overflow-x-auto rounded-md bg-surface-2 px-3 py-2 font-mono text-xs text-muted">
                    {f.snippet}
                  </pre>
                ) : null}
                {f.remediation ? <p className="mt-2 text-sm text-fg">{f.remediation}</p> : null}
              </li>
            ))}
          </ul>
        )}
        {report.packages.length ? (
          <>
            <Separator />
            <p className="text-sm font-medium">Pacotes ({report.packages.length})</p>
            <div className="max-h-64 overflow-auto rounded-lg border border-border">
              <table className="w-full text-left text-xs">
                <thead className="bg-surface-2 text-muted">
                  <tr>
                    <th className="px-3 py-2 font-medium">Nome</th>
                    <th className="px-3 py-2 font-medium">Versão</th>
                    <th className="px-3 py-2 font-medium">Eco</th>
                    <th className="px-3 py-2 font-medium">Escopo</th>
                  </tr>
                </thead>
                <tbody>
                  {report.packages.slice(0, 80).map((p) => (
                    <tr key={`${p.ecosystem}:${p.name}@${p.version}`} className="border-t border-border">
                      <td className="px-3 py-2 font-mono">{p.name}</td>
                      <td className="px-3 py-2 font-mono tabular-nums">{p.version ?? "—"}</td>
                      <td className="px-3 py-2">{p.ecosystem}</td>
                      <td className="px-3 py-2">{p.scope}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

function EmptyState() {
  return (
    <Card>
      <CardContent className="flex flex-col items-start gap-3 py-10">
        <Box className="size-6 text-muted" />
        <div>
          <p className="font-medium">Pronto para auditar</p>
          <p className="max-w-lg text-sm text-muted">
            Cole um package.json, requirements.txt, go.mod ou um trecho de código. O Sentinel consulta o OSV.dev em
            lote e cruza com regras SAST, Docker e higiene de supply chain.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

function SeverityBar({ stats }: { stats: ScanStats }) {
  const parts: { tone: string; n: number }[] = [
    { tone: "bg-critical", n: stats.critical },
    { tone: "bg-high", n: stats.high },
    { tone: "bg-medium", n: stats.medium },
    { tone: "bg-low", n: stats.low },
    { tone: "bg-info", n: stats.info },
  ];
  const total = parts.reduce((s, p) => s + p.n, 0);
  return (
    <div className="flex h-2 overflow-hidden rounded-full bg-surface-2">
      {total === 0 ? <div className="h-full w-full bg-surface-2" /> : null}
      {parts.map((p, i) =>
        p.n ? <div key={i} className={`h-full ${p.tone}`} style={{ flexGrow: p.n }} /> : null,
      )}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone: Severity }) {
  return (
    <div className="rounded-lg border border-border bg-bg px-3 py-2">
      <p className="text-xs text-subtle">{label}</p>
      <p
        className={`font-mono text-lg tabular-nums ${
          tone === "critical"
            ? "text-critical"
            : tone === "high"
              ? "text-high"
              : tone === "medium"
                ? "text-medium"
                : tone === "low"
                  ? "text-low"
                  : "text-info"
        }`}
      >
        {value}
      </p>
    </div>
  );
}

function RiskMeter({ score }: { score: number }) {
  const tone = score >= 70 ? "text-critical" : score >= 40 ? "text-high" : score >= 20 ? "text-medium" : "text-low";
  return (
    <div className="flex size-20 flex-col items-center justify-center rounded-xl border border-border bg-bg">
      <span className={`font-mono text-2xl tabular-nums ${tone}`}>{score}</span>
      <span className="text-xs uppercase tracking-wider text-subtle">risco</span>
    </div>
  );
}

function CloudBadge({ status }: { status: CloudStatus }) {
  if (status === "ok") {
    return (
      <Badge tone="low">
        <Cloud className="mr-1 size-3" /> Supabase
      </Badge>
    );
  }
  if (status === "missing-table") {
    return (
      <Badge tone="medium">
        <AlertTriangle className="mr-1 size-3" /> Tabela scans
      </Badge>
    );
  }
  return (
    <Badge>
      <CloudOff className="mr-1 size-3" /> Local
    </Badge>
  );
}

function labelFilter(key: string): string {
  const map: Record<string, string> = {
    all: "Todos",
    critical: "Crítico",
    high: "Alto",
    medium: "Médio",
    vuln: "OSV",
    secret: "Segredos",
    sast: "SAST",
    hygiene: "Higiene",
  };
  return map[key] ?? key;
}
