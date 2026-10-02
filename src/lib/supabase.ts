import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { ScanReport, ScanSummary } from "./types";

export const SUPABASE_URL =
  (import.meta.env.VITE_SUPABASE_URL as string | undefined) ||
  "https://pewhzyjibtfnnvevizpm.supabase.co";

export const SUPABASE_KEY =
  (import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY as string | undefined) ||
  "sb_publishable_5LNs9-plVBvC82tbanw9fw_QyqklYNv";

export const SCANS_DDL = `create table if not exists public.scans (
  id uuid primary key,
  created_at timestamptz not null default now(),
  title text not null,
  source_kind text not null,
  package_count int not null default 0,
  finding_count int not null default 0,
  critical_count int not null default 0,
  high_count int not null default 0,
  medium_count int not null default 0,
  low_count int not null default 0,
  risk_score int not null default 0,
  summary jsonb not null default '{}'::jsonb
);
alter table public.scans enable row level security;
drop policy if exists scans_read on public.scans;
drop policy if exists scans_insert on public.scans;
create policy "scans_read" on public.scans for select using (true);
create policy "scans_insert" on public.scans for insert with check (true);`;

const LOCAL_KEY = "sentinel.scans.v1";
const FULL_KEY = "sentinel.full.v1";

let client: SupabaseClient | null = null;
let tableReady: boolean | null = null;

export type CloudStatus = "ok" | "missing-table" | "offline";

export function getSupabase(): SupabaseClient {
  if (!client) client = createClient(SUPABASE_URL, SUPABASE_KEY);
  return client;
}

export async function probeCloud(): Promise<CloudStatus> {
  try {
    const { error } = await getSupabase().from("scans").select("id").limit(1);
    if (!error) {
      tableReady = true;
      return "ok";
    }
    const msg = error.message || "";
    if (msg.includes("schema cache") || msg.includes("does not exist") || error.code === "PGRST205") {
      tableReady = false;
      return "missing-table";
    }
    tableReady = false;
    return "offline";
  } catch {
    tableReady = false;
    return "offline";
  }
}

export function toSummary(report: ScanReport, remote = false): ScanSummary {
  return {
    id: report.id,
    createdAt: report.createdAt,
    title: report.title,
    sourceKind: report.sourceKind,
    packageCount: report.stats.packages,
    findingCount: report.stats.findings,
    criticalCount: report.stats.critical,
    highCount: report.stats.high,
    mediumCount: report.stats.medium,
    lowCount: report.stats.low,
    riskScore: report.riskScore,
    remote,
    top: report.findings.slice(0, 20).map((f) => ({
      id: f.id,
      kind: f.kind,
      severity: f.severity,
      title: f.title,
      packageName: f.packageName,
      osvId: f.osvId,
      fixedVersion: f.fixedVersion,
    })),
  };
}

export function loadLocalHistory(): ScanSummary[] {
  if (typeof localStorage === "undefined") return [];
  try {
    const raw = localStorage.getItem(LOCAL_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as ScanSummary[];
  } catch {
    return [];
  }
}

function localSave(rows: ScanSummary[]) {
  localStorage.setItem(LOCAL_KEY, JSON.stringify(rows.slice(0, 40)));
}

export function saveFullReport(report: ScanReport) {
  if (typeof localStorage === "undefined") return;
  try {
    const raw = localStorage.getItem(FULL_KEY);
    const map = raw ? (JSON.parse(raw) as Record<string, ScanReport>) : {};
    map[report.id] = report;
    const ids = Object.keys(map);
    if (ids.length > 8) {
      for (const id of ids.slice(0, ids.length - 8)) delete map[id];
    }
    localStorage.setItem(FULL_KEY, JSON.stringify(map));
  } catch {
    /* quota */
  }
}

export function loadFullReport(id: string): ScanReport | null {
  if (typeof localStorage === "undefined") return null;
  try {
    const raw = localStorage.getItem(FULL_KEY);
    if (!raw) return null;
    const map = JSON.parse(raw) as Record<string, ScanReport>;
    return map[id] ?? null;
  } catch {
    return null;
  }
}

export async function persistScan(report: ScanReport): Promise<{ summary: ScanSummary; cloud: CloudStatus }> {
  const summary = toSummary(report, false);
  const local = [summary, ...loadLocalHistory().filter((s) => s.id !== summary.id)];
  localSave(local);
  saveFullReport(report);

  const payload = {
    id: report.id,
    created_at: report.createdAt,
    title: report.title,
    source_kind: report.sourceKind,
    package_count: report.stats.packages,
    finding_count: report.stats.findings,
    critical_count: report.stats.critical,
    high_count: report.stats.high,
    medium_count: report.stats.medium,
    low_count: report.stats.low,
    risk_score: report.riskScore,
    summary: {
      stats: report.stats,
      notes: report.notes.slice(0, 12),
      top: summary.top,
    },
  };

  try {
    if (tableReady === false) return { summary, cloud: "missing-table" };
    const { error } = await getSupabase().from("scans").insert(payload);
    if (!error) {
      tableReady = true;
      return { summary: { ...summary, remote: true }, cloud: "ok" };
    }
    if (error.message?.includes("schema cache") || error.code === "PGRST205") {
      tableReady = false;
      return { summary, cloud: "missing-table" };
    }
    return { summary, cloud: "offline" };
  } catch {
    return { summary, cloud: "offline" };
  }
}

export async function loadHistory(): Promise<{ rows: ScanSummary[]; cloud: CloudStatus }> {
  const local = loadLocalHistory();
  try {
    const { data, error } = await getSupabase()
      .from("scans")
      .select(
        "id, created_at, title, source_kind, package_count, finding_count, critical_count, high_count, medium_count, low_count, risk_score, summary",
      )
      .order("created_at", { ascending: false })
      .limit(40);
    if (error) {
      const cloud = await probeCloud();
      return { rows: local, cloud };
    }
    tableReady = true;
    const remote: ScanSummary[] = (data ?? []).map((row) => {
      const summary = (row.summary ?? {}) as { top?: ScanSummary["top"] };
      return {
        id: row.id as string,
        createdAt: row.created_at as string,
        title: row.title as string,
        sourceKind: row.source_kind as ScanSummary["sourceKind"],
        packageCount: Number(row.package_count) || 0,
        findingCount: Number(row.finding_count) || 0,
        criticalCount: Number(row.critical_count) || 0,
        highCount: Number(row.high_count) || 0,
        mediumCount: Number(row.medium_count) || 0,
        lowCount: Number(row.low_count) || 0,
        riskScore: Number(row.risk_score) || 0,
        remote: true,
        top: summary.top,
      };
    });
    const merged = new Map<string, ScanSummary>();
    for (const row of [...remote, ...local]) {
      const prev = merged.get(row.id);
      merged.set(row.id, prev ? { ...row, ...prev, remote: prev.remote || row.remote, top: prev.top ?? row.top } : row);
    }
    const rows = [...merged.values()].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    return { rows, cloud: "ok" };
  } catch {
    return { rows: local, cloud: "offline" };
  }
}
