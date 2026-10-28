-- HalterEGO: tabelas, privacidade (RLS) e limite de vagas.
-- Rode no Supabase: SQL Editor > New query > cole tudo > Run. Pode rodar de novo sem problema.

create table if not exists public.config (
  id int primary key default 1 check (id = 1),
  limite int not null default 10
);
insert into public.config (id, limite) values (1, 10) on conflict (id) do nothing;

create table if not exists public.admins (email text primary key);
-- >>> TROQUE pelo e-mail com o qual você vai entrar no app. Só este e-mail vê os perfis dos outros.
insert into public.admins (email) values ('SEU_EMAIL_AQUI') on conflict (email) do nothing;

-- convidados: só quem estiver nesta lista (ou for o administrador) consegue criar perfil. O admin gerencia a lista no app.
create table if not exists public.convidados (email text primary key, criado timestamptz not null default now());

create table if not exists public.membros (
  uid uuid primary key references auth.users(id) on delete cascade,
  email text,
  dados jsonb not null default '{}'::jsonb,
  desde timestamptz not null default now()
);
create table if not exists public.perfis (
  uid uuid primary key references auth.users(id) on delete cascade,
  dados jsonb not null,
  atualizado timestamptz not null default now()
);
create table if not exists public.registros (
  uid uuid not null references auth.users(id) on delete cascade,
  id text not null,
  dados jsonb not null,
  atualizado timestamptz not null default now(),
  primary key (uid, id)
);

alter table public.config enable row level security;
alter table public.admins enable row level security;
alter table public.convidados enable row level security;
alter table public.membros enable row level security;
alter table public.perfis enable row level security;
alter table public.registros enable row level security;

create or replace function public.sou_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')))
$$;
create or replace function public.vagas_livres() returns boolean
language sql stable security definer set search_path = public as $$
  select (select count(*) from public.membros) < (select limite from public.config where id = 1)
$$;
create or replace function public.convidado() returns boolean
language sql stable security definer set search_path = public as $$
  select public.sou_admin() or exists (select 1 from public.convidados where lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')))
$$;
revoke all on function public.sou_admin(), public.vagas_livres(), public.convidado() from public, anon;
grant execute on function public.sou_admin(), public.vagas_livres(), public.convidado() to authenticated;

-- config: todos leem, só o admin altera (ex.: update public.config set limite = 15;)
drop policy if exists config_ler on public.config;
create policy config_ler on public.config for select to authenticated using (true);
drop policy if exists config_alterar on public.config;
create policy config_alterar on public.config for update to authenticated using (public.sou_admin()) with check (public.sou_admin());

-- admins: cada pessoa só enxerga a própria linha (serve para o app saber se você é o administrador)
drop policy if exists admins_ler on public.admins;
create policy admins_ler on public.admins for select to authenticated using (lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')));

-- convidados: só o admin lê e altera
drop policy if exists convidados_admin on public.convidados;
create policy convidados_admin on public.convidados for all to authenticated using (public.sou_admin()) with check (public.sou_admin());

-- membros: entrar só se estiver convidado e houver vaga (limite aplicado no servidor); o admin vê todos e pode liberar vagas
drop policy if exists membros_ler on public.membros;
create policy membros_ler on public.membros for select to authenticated using (uid = auth.uid() or public.sou_admin());
drop policy if exists membros_entrar on public.membros;
create policy membros_entrar on public.membros for insert to authenticated with check (uid = auth.uid() and public.convidado() and public.vagas_livres());
drop policy if exists membros_atualizar on public.membros;
create policy membros_atualizar on public.membros for update to authenticated using (uid = auth.uid()) with check (uid = auth.uid());
drop policy if exists membros_remover on public.membros;
create policy membros_remover on public.membros for delete to authenticated using (public.sou_admin());

-- perfis: cada pessoa lê e grava só o seu; o admin lê todos e pode apagar (direito de exclusão)
drop policy if exists perfis_ler on public.perfis;
create policy perfis_ler on public.perfis for select to authenticated using (uid = auth.uid() or public.sou_admin());
drop policy if exists perfis_criar on public.perfis;
create policy perfis_criar on public.perfis for insert to authenticated with check (uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid()));
drop policy if exists perfis_atualizar on public.perfis;
create policy perfis_atualizar on public.perfis for update to authenticated using (uid = auth.uid()) with check (uid = auth.uid());
drop policy if exists perfis_remover on public.perfis;
create policy perfis_remover on public.perfis for delete to authenticated using (uid = auth.uid() or public.sou_admin());

-- registros (treinos): mesma regra dos perfis
drop policy if exists registros_ler on public.registros;
create policy registros_ler on public.registros for select to authenticated using (uid = auth.uid() or public.sou_admin());
drop policy if exists registros_criar on public.registros;
create policy registros_criar on public.registros for insert to authenticated with check (uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid()));
drop policy if exists registros_atualizar on public.registros;
create policy registros_atualizar on public.registros for update to authenticated using (uid = auth.uid()) with check (uid = auth.uid());
drop policy if exists registros_remover on public.registros;
create policy registros_remover on public.registros for delete to authenticated using (uid = auth.uid() or public.sou_admin());

-- o app só usa usuários logados: sem acesso para quem não está autenticado
revoke all on public.config, public.admins, public.convidados, public.membros, public.perfis, public.registros from anon;
grant select, insert, update, delete on public.config, public.admins, public.convidados, public.membros, public.perfis, public.registros to authenticated;

-- ===== endurecimento (segurança) =====
create or replace function public.bloqueia_nao_convidado() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if exists (select 1 from public.admins where lower(email) = lower(new.email))
     or exists (select 1 from public.convidados where lower(email) = lower(new.email)) then
    return new;
  end if;
  raise exception 'E-mail nao convidado';
end $$;
drop trigger if exists bloqueia_nao_convidado on auth.users;
create trigger bloqueia_nao_convidado before insert on auth.users for each row execute function public.bloqueia_nao_convidado();

create or replace function public.limita_membros() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform pg_advisory_xact_lock(7001);
  if (select count(*) from public.membros) >= (select limite from public.config where id = 1) then
    raise exception 'Vagas preenchidas';
  end if;
  return new;
end $$;
drop trigger if exists limita_membros on public.membros;
create trigger limita_membros before insert on public.membros for each row execute function public.limita_membros();

drop policy if exists perfis_ler on public.perfis;
create policy perfis_ler on public.perfis for select to authenticated using ((uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid())) or public.sou_admin());
drop policy if exists perfis_atualizar on public.perfis;
create policy perfis_atualizar on public.perfis for update to authenticated using (uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid())) with check (uid = auth.uid());
drop policy if exists registros_ler on public.registros;
create policy registros_ler on public.registros for select to authenticated using ((uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid())) or public.sou_admin());
drop policy if exists registros_atualizar on public.registros;
create policy registros_atualizar on public.registros for update to authenticated using (uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid())) with check (uid = auth.uid());

alter table public.perfis drop constraint if exists perfis_tam;
alter table public.perfis add constraint perfis_tam check (pg_column_size(dados) < 200000);
alter table public.registros drop constraint if exists registros_tam;
alter table public.registros add constraint registros_tam check (pg_column_size(dados) < 100000);
alter table public.membros drop constraint if exists membros_tam;
alter table public.membros add constraint membros_tam check (pg_column_size(dados) < 2000);
