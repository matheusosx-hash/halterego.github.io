-- HalterEGO: tabelas, privacidade (RLS) e limite de vagas.
-- Rode no Supabase: SQL Editor > New query > cole tudo > Run. Pode rodar de novo sem problema.

create table if not exists public.config (
  id int primary key default 1 check (id = 1),
  limite int not null default 30
);
insert into public.config (id, limite) values (1, 30) on conflict (id) do update set limite = 30;

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
  select auth.uid() is not null  -- acesso aberto: quem criou login e senha entra direto (limite de vagas continua valendo)
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
drop trigger if exists bloqueia_nao_convidado on auth.users;  -- sem aprovação: o cadastro por e-mail e senha é livre

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

-- ===== aprovação de acesso (pedido + aprovação pelo administrador) =====
create table if not exists public.solicitacoes (
  email text primary key,
  nome text not null default '',
  status text not null default 'pendente' check (status in ('pendente', 'aprovada', 'recusada')),
  criado timestamptz not null default now(),
  decidido timestamptz
);
alter table public.solicitacoes enable row level security;
drop policy if exists solicitacoes_admin on public.solicitacoes;
create policy solicitacoes_admin on public.solicitacoes for all to authenticated using (public.sou_admin()) with check (public.sou_admin());
revoke all on public.solicitacoes from anon;
grant select, insert, update, delete on public.solicitacoes to authenticated;

create or replace function public.pedir_acesso(p_email text, p_nome text) returns text
language plpgsql security definer set search_path = public as $$
declare e text := lower(trim(coalesce(p_email, ''))); n text := left(trim(coalesce(p_nome, '')), 80); r text;
begin
  if e !~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$' or length(e) > 254 then raise exception 'E-mail invalido'; end if;
  if (select count(*) from public.solicitacoes where status = 'pendente') >= 50 then raise exception 'Muitos pedidos'; end if;
  insert into public.solicitacoes (email, nome) values (e, n)
    on conflict (email) do update set nome = case when public.solicitacoes.status = 'pendente' then excluded.nome else public.solicitacoes.nome end;
  select status into r from public.solicitacoes where email = e;
  if r = 'aprovada' and not exists (select 1 from public.convidados where lower(email) = e) and not exists (select 1 from public.admins where lower(email) = e) then
    insert into public.convidados (email) values (e) on conflict (email) do nothing;
  end if;
  return r;
end $$;
revoke all on function public.pedir_acesso(text, text) from public;
grant execute on function public.pedir_acesso(text, text) to anon, authenticated;

create or replace function public.decidir_acesso(p_email text, p_aprova boolean) returns void
language plpgsql security definer set search_path = public as $$
declare e text := lower(trim(coalesce(p_email, '')));
begin
  if not public.sou_admin() then raise exception 'Negado'; end if;
  if p_aprova then
    insert into public.convidados (email) values (e) on conflict (email) do nothing;
    update public.solicitacoes set status = 'aprovada', decidido = now() where email = e;
  else
    delete from public.convidados where lower(email) = e;
    update public.solicitacoes set status = 'recusada', decidido = now() where email = e;
  end if;
end $$;
revoke all on function public.decidir_acesso(text, boolean) from public, anon;
grant execute on function public.decidir_acesso(text, boolean) to authenticated;

-- ===== feed (publicações de treino) =====
create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  uid uuid not null references auth.users(id) on delete cascade,
  nome text not null default '',
  texto text not null default '',
  imagem text not null,
  criado timestamptz not null default now(),
  check (char_length(texto) <= 200),
  check (imagem like 'data:image/jpeg;base64,%' and char_length(imagem) < 400000)
);
create index if not exists posts_criado on public.posts (criado desc);
alter table public.posts enable row level security;

create or replace function public.posts_antes_de_inserir() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.nome := coalesce((select split_part(coalesce(dados->'anamnese'->>'nome', ''), ' ', 1) from public.perfis where uid = new.uid), '');
  new.criado := now();
  if (select count(*) from public.posts where uid = new.uid and criado > now() - interval '24 hours') >= 10 then
    raise exception 'Limite de publicacoes por dia';
  end if;
  return new;
end $$;
drop trigger if exists posts_antes_de_inserir on public.posts;
create trigger posts_antes_de_inserir before insert on public.posts for each row execute function public.posts_antes_de_inserir();

drop policy if exists posts_ler on public.posts;
create policy posts_ler on public.posts for select to authenticated using (exists (select 1 from public.membros m where m.uid = auth.uid()) or public.sou_admin());
drop policy if exists posts_criar on public.posts;
create policy posts_criar on public.posts for insert to authenticated with check (uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid()));
drop policy if exists posts_apagar on public.posts;
create policy posts_apagar on public.posts for delete to authenticated using (uid = auth.uid() or public.sou_admin());
revoke all on public.posts from anon;
grant select, insert, delete on public.posts to authenticated;
-- ===== mini rede social: perfil público, curtidas, comentários, novidades =====
create table if not exists public.perfil_publico (
  uid uuid primary key references auth.users(id) on delete cascade,
  nome text not null default '', bio text not null default '', foto text,
  atualizado timestamptz not null default now(),
  check (char_length(nome) <= 40), check (char_length(bio) <= 120),
  check (foto is null or (foto like 'data:image/jpeg;base64,%' and char_length(foto) < 60000))
);
alter table public.perfil_publico enable row level security;
drop policy if exists pp_ler on public.perfil_publico;
create policy pp_ler on public.perfil_publico for select to authenticated using (exists (select 1 from public.membros m where m.uid = auth.uid()) or public.sou_admin());
drop policy if exists pp_inserir on public.perfil_publico;
create policy pp_inserir on public.perfil_publico for insert to authenticated with check (uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid()));
drop policy if exists pp_mudar on public.perfil_publico;
create policy pp_mudar on public.perfil_publico for update to authenticated using (uid = auth.uid()) with check (uid = auth.uid());
revoke all on public.perfil_publico from anon;
grant select, insert, update on public.perfil_publico to authenticated;

create table if not exists public.curtidas (
  post_id uuid not null references public.posts(id) on delete cascade,
  uid uuid not null references auth.users(id) on delete cascade,
  primary key (post_id, uid)
);
alter table public.curtidas enable row level security;
drop policy if exists cur_ler on public.curtidas;
create policy cur_ler on public.curtidas for select to authenticated using (exists (select 1 from public.membros m where m.uid = auth.uid()) or public.sou_admin());
drop policy if exists cur_criar on public.curtidas;
create policy cur_criar on public.curtidas for insert to authenticated with check (uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid()));
drop policy if exists cur_apagar on public.curtidas;
create policy cur_apagar on public.curtidas for delete to authenticated using (uid = auth.uid());
revoke all on public.curtidas from anon;
grant select, insert, delete on public.curtidas to authenticated;

create table if not exists public.comentarios (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  uid uuid not null references auth.users(id) on delete cascade,
  texto text not null, criado timestamptz not null default now(),
  check (char_length(texto) between 1 and 200)
);
create index if not exists comentarios_post on public.comentarios (post_id, criado);
alter table public.comentarios enable row level security;
drop policy if exists com_ler on public.comentarios;
create policy com_ler on public.comentarios for select to authenticated using (exists (select 1 from public.membros m where m.uid = auth.uid()) or public.sou_admin());
drop policy if exists com_criar on public.comentarios;
create policy com_criar on public.comentarios for insert to authenticated with check (uid = auth.uid() and exists (select 1 from public.membros m where m.uid = auth.uid()));
drop policy if exists com_apagar on public.comentarios;
create policy com_apagar on public.comentarios for delete to authenticated using (uid = auth.uid() or public.sou_admin());
revoke all on public.comentarios from anon;
grant select, insert, delete on public.comentarios to authenticated;

create table if not exists public.novidades (
  id uuid primary key default gen_random_uuid(),
  titulo text not null, texto text not null, criado timestamptz not null default now(),
  check (char_length(titulo) <= 80), check (char_length(texto) <= 600)
);
alter table public.novidades enable row level security;
drop policy if exists nov_ler on public.novidades;
create policy nov_ler on public.novidades for select to authenticated using (exists (select 1 from public.membros m where m.uid = auth.uid()) or public.sou_admin());
drop policy if exists nov_escrever on public.novidades;
create policy nov_escrever on public.novidades for all to authenticated using (public.sou_admin()) with check (public.sou_admin());
revoke all on public.novidades from anon;
grant select, insert, update, delete on public.novidades to authenticated;

insert into public.novidades (titulo, texto, criado)
select t, x, c from (values
  ('Feed e perfil', 'Agora o app tem um feed: publique o card do seu treino com um texto curto, curta e comente os treinos da galera. Complete seu perfil com foto e bio em Perfil.', now()),
  ('Cronômetro de treino', 'Toque em Iniciar treino e em Terminar quando acabar: o tempo total, com pausas, entra no card.', now() - interval '1 day'),
  ('Evolução na página inicial', 'A aba Evolução mostra semana e mês, recordes, sequência e cards prontos para os Stories.', now() - interval '2 days')
) v(t, x, c) where not exists (select 1 from public.novidades);
-- ===== endurecimento: imagens só JPEG base64 válido, nome oficial reservado, limite de comentários =====
create or replace function public.valida_post() returns trigger language plpgsql as $$
begin
  if new.imagem !~ '^data:image/jpeg;base64,[A-Za-z0-9+/=]+$' or char_length(new.imagem) > 400000 then raise exception 'Imagem invalida'; end if;
  return new;
end $$;
drop trigger if exists valida_post on public.posts;
create trigger valida_post before insert on public.posts for each row execute function public.valida_post();

create or replace function public.valida_perfil_publico() returns trigger language plpgsql as $$
begin
  if new.foto is not null and (new.foto !~ '^data:image/jpeg;base64,[A-Za-z0-9+/=]+$' or char_length(new.foto) > 60000) then raise exception 'Foto invalida'; end if;
  if lower(regexp_replace(new.nome, '\s', '', 'g')) like '%halterego%' then raise exception 'Nome reservado'; end if;
  return new;
end $$;
drop trigger if exists valida_perfil_publico on public.perfil_publico;
create trigger valida_perfil_publico before insert or update on public.perfil_publico for each row execute function public.valida_perfil_publico();

create or replace function public.limita_comentarios() returns trigger language plpgsql as $$
begin
  if (select count(*) from public.comentarios where uid = new.uid and criado > now() - interval '24 hours') >= 100 then raise exception 'Limite de comentarios por dia'; end if;
  return new;
end $$;
drop trigger if exists limita_comentarios on public.comentarios;
create trigger limita_comentarios before insert on public.comentarios for each row execute function public.limita_comentarios();
