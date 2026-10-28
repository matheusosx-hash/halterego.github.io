# HalterEGO no GitHub Pages (com login e painel do administrador)

O site é estático (`index.html` + `config.js`). Login, dados por pessoa, painel só seu e as 10 vagas ficam no Supabase (gratuito).

## 1. Criar o projeto no Supabase (uma vez)
1. Entre em supabase.com, crie um projeto (qualquer região, guarde a senha do banco).
2. **SQL Editor > New query**: abra `supabase.sql`, troque `SEU_EMAIL_AQUI` pelo e-mail com o qual você vai entrar no app, cole tudo e clique em **Run**.
3. **Project Settings > API**: copie a **Project URL** e a chave **anon / publishable**. Cole em `config.js`.
   - Nunca coloque a chave `service_role` no GitHub.
4. **Authentication > Providers**: deixe **Email** ligado (link mágico, sem senha).
5. **Authentication > URL Configuration**: em **Site URL** coloque o endereço do seu site no GitHub Pages (ex.: `https://seuusuario.github.io/halterego/`) e adicione o mesmo endereço em **Redirect URLs**.

## 2. Publicar no GitHub Pages
1. Crie um repositório e suba **`index.html`, `config.js` e `supabase.sql`** (pode subir o README também). Não suba arquivos `backup-*.json`.
2. **Settings > Pages**: Source = *Deploy from a branch*, branch `main`, pasta `/ (root)`.
3. O endereço fica `https://SEU-USUARIO.github.io/NOME-DO-REPOSITORIO/` (repositório de projeto) ou `https://SEU-USUARIO.github.io/` se o repositório se chamar `SEU-USUARIO.github.io`.
4. Abra o endereço do Pages, digite seu e-mail e abra o link que chega. A primeira pessoa a entrar com o e-mail do administrador vê **Perfil > Pessoas do app**.

## 3. Como funciona a privacidade
- Cada pessoa só lê e grava os próprios dados (regras RLS no `supabase.sql`).
- **Só o e-mail da tabela `admins`** lê os perfis e treinos de todos. Usuários não veem uns aos outros.
- **Só entra quem foi convidado**: o administrador cadastra os e-mails em Perfil > Pessoas do app > Convidados. Quem não estiver na lista não consegue criar perfil, mesmo com o link.
- O limite de **10 pessoas é aplicado no servidor**: a 11ª recebe a mensagem de vagas preenchidas. Para mudar: `update public.config set limite = 15;`
- Para liberar uma vaga ou apagar os dados de alguém (direito de exclusão), apague a linha da pessoa em `membros` (e `perfis`/`registros`) no Supabase, ou apague o usuário em Authentication > Users.
- Os dados incluem informações de saúde. Avise as pessoas de que o administrador consegue ver (o cadastro e o Perfil já dizem isso) e não compartilhe prints do painel.

## 4. Levar seus dados do app antigo
O arquivo `backup-treino.json` (gerado na sua máquina, fora do repositório) tem seu perfil e seus treinos. Entre no site já logado, abra **Perfil > Importar backup (.json)** e escolha o arquivo.

## 5. Limites do plano gratuito
O Supabase gratuito pausa o projeto após uma semana sem uso. Se isso acontecer, entre no painel do Supabase e clique em *Restore*.
