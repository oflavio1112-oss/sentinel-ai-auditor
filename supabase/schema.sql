-- Cole no SQL Editor do Supabase (https://supabase.com/dashboard/project/pewhzyjibtfnnvevizpm/sql)
-- A chave publishable só consegue ler/inserir depois que esta tabela existir.

create table if not exists public.scans (
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
create policy scans_read on public.scans for select using (true);
create policy scans_insert on public.scans for insert with check (true);
