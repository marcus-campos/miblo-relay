# Miblo relay

**Português** · [English](#english)

O servidor do celular do [Miblo](https://miblo.ai), para você subir no seu próprio host: o relay
das sessões, a conta em que os seus celulares entram, o registro de celulares e o app do celular
(PWA). É o mesmo protocolo que o plugin do Miblo e o miblo.ai usam, então tudo do Miblo+ que passa
pelo celular (histórico, respostas, aprovações, tarefas remotas) funciona aqui, **de graça e sem
licença**, para quem subir o próprio servidor.

- [Como funciona a privacidade](#privacidade)
- [Subir em 3 passos (Docker)](#subir-em-3-passos-docker)
- [Na sua própria conta Cloudflare](#na-sua-própria-conta-cloudflare)
- [Apontar o seu computador para ele](#apontar-o-seu-computador-para-ele)
- [Configuração](#configuração) · [Atualizar](#atualizar) · [Segurança](#segurança) · [Builds reproduzíveis](#builds-reproduzíveis) · [Licença](#licença)

## Privacidade

O Miblo já é cifrado de ponta a ponta: as chaves nascem no seu computador, chegam a cada celular
seladas para a chave daquele celular, só depois que você digita no computador o código de 6
dígitos que o celular mostra, e o servidor só repassa dados cifrados. Um servidor malicioso (o
miblo.ai ou este) não lê nada, não coloca um celular dele no lugar do seu e não age no seu
computador.

O que sobra é **o código do app do celular**: ele é uma página web, e quem serve a página roda
código com as chaves do celular. No miblo.ai, você confia no que o miblo.ai serve. **No seu
servidor, o app é o que você compilou deste código** (ou uma versão cujos hashes você conferiu),
servido por você. Isso tira a confiança no JavaScript servido pelo miblo.ai. Detalhes no
[modelo de ameaças](docs/threat-model.md).

Enquanto o seu servidor estiver configurado, o plugin não manda nada do celular nem da conta para o
miblo.ai (ele só continua lendo do miblo.ai o manifesto assinado de atualizações).

## Subir em 3 passos (Docker)

Você precisa de uma máquina com Docker, um nome DNS apontando para ela e as portas 80 e 443 abertas
(o Caddy pega o certificado TLS sozinho).

1. **Baixar e configurar**
   ```sh
   git clone https://github.com/marcus-campos/miblo-relay.git && cd miblo-relay/deploy/docker
   cp .env.example .env   # coloque o seu domínio em RELAY_DOMAIN
   ```
2. **Subir**
   ```sh
   docker compose up -d --build
   docker compose logs relay   # mostra o código de configuração e a impressão digital do servidor
   ```
3. **Criar a sua conta**: abra `https://seu-dominio/conta`, use o código de configuração, crie a
   senha e adicione um segundo fator (passkey recomendada, ou app autenticador). Gere os códigos de
   recuperação.

Depois, no computador: [apontar o plugin para o seu servidor](#apontar-o-seu-computador-para-ele).
Sem Docker: `npm ci && npm run build && PUBLIC_ORIGIN=https://seu-dominio node dist/server.mjs`
(Node 22.13+ ou 23.4+, que têm `node:sqlite`) atrás de qualquer proxy com TLS.

## Na sua própria conta Cloudflare

Roda como um Worker na **sua** conta Cloudflare (o plano gratuito basta para uma pessoa), com D1 e
Durable Objects:

```sh
npm ci
cp deploy/cloudflare/wrangler.jsonc.example deploy/cloudflare/wrangler.jsonc
cd deploy/cloudflare
npx wrangler d1 create miblo-relay          # coloque o database_id no wrangler.jsonc
# em wrangler.jsonc: PUBLIC_ORIGIN = o endereço https do seu Worker (ou do seu domínio)
npx wrangler d1 migrations apply miblo-relay --remote
cd ../.. && npm run build:app && npm run cf:secrets   # mostra o código de configuração e a impressão digital
cd deploy/cloudflare && npx wrangler deploy
```

Depois, o passo 3 acima (`https://seu-endereço/conta`).

## Apontar o seu computador para ele

No **seu** terminal (nunca por um agente de IA), com o plugin do Miblo na versão que tem
`miblo server`:

```sh
miblo server set https://seu-dominio
```

O Miblo lê a chave de identidade do servidor, mostra a impressão digital (compare com a que o
**seu** servidor mostrou no log: `docker compose logs relay` ou `node dist/server.mjs fingerprint`)
e pede o código que aparece na tela do seu Miblo. No app Miblo do computador: **Ajustes › Servidor
do celular**. Trocar de servidor desvincula este computador e desliga o celular no servidor antigo;
depois:

```sh
miblo account link   # confirme o código em https://seu-dominio/plus/link
miblo phone on
```

No celular, abra `https://seu-dominio/app`, entre na sua conta e permita o celular no computador
com o código que ele mostra. `miblo server` mostra para onde aponta; `miblo server reset` volta para
o miblo.ai (também com o código do Miblo).

## Configuração

| Variável | Obrigatória | O que é |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | sim | O endereço https do servidor, só a origem (`https://relay.exemplo.com`). É a origem do app, o relying party das passkeys e o endereço do link de vinculação. Nunca vem da requisição. |
| `TRUSTED_PROXY` | atrás de proxy | Os endereços ou faixas (CIDR) do seu proxy, separados por vírgula (`172.30.247.0/24`). Só de uma conexão vinda deles o endereço do cliente é a última entrada do `X-Forwarded-For` (a que o proxy colocou). Só usado como chave de limite de taxa. Não defina sem um proxy na frente. |
| `RELAY_VAPID_SUBJECT` | não | Contato enviado aos serviços de push (`mailto:voce@exemplo.com`); sem ele, o endereço do servidor. |
| `SESSION_SECRET`, `MFA_KEY`, `SERVER_IDENTITY_KEY`, `RELAY_VAPID_PUBLIC_KEY`, `RELAY_VAPID_PRIVATE_KEY`, `SETUP_TOKEN` | não (Node) / sim (Cloudflare) | No Node, os que você não definir são criados uma vez e guardados em `secrets.json` (0600), na pasta `$MIBLO_RELAY_SECRETS_DIR`. Na Cloudflare, `npm run cf:secrets` cria e guarda todos. |
| `MIBLO_RELAY_DATA` | não | Pasta do banco (Docker: `/data`). |
| `MIBLO_RELAY_SECRETS_DIR` | não | Pasta do `secrets.json` (padrão: `MIBLO_RELAY_DATA`; Docker: `/secrets`, um volume à parte, fora dos backups do banco). |
| `PORT`, `HOST` | não | Onde o Node escuta (padrão `0.0.0.0:8787`). |

Comandos do Node: `node dist/server.mjs check` (confere a configuração), `fingerprint`,
`setup-token` (o código de configuração vale para uma configuração só; depois de usado, este
comando gera outro, para refazer uma configuração abandonada), `reset-account` (perdeu todos os
fatores: apaga fatores e sessões e gera um novo código de configuração; computadores e celulares
continuam). Na Cloudflare, para o mesmo efeito, apague as linhas de `mfa_*` e `sessions` com
`wrangler d1 execute` e defina um novo código com `npx wrangler secret put SETUP_TOKEN` (um valor
aleatório longo, como `openssl rand -base64 24`).

## Atualizar

```sh
git pull && cd deploy/docker && docker compose up -d --build
```

As migrações do banco rodam sozinhas ao subir (Node). Na Cloudflare:
`npx wrangler d1 migrations apply miblo-relay --remote && npm run build:app && npx wrangler deploy`.
Acompanhe as releases do repositório: correções de segurança vêm marcadas. Faça backup do volume
`relay-data` (Docker) antes de atualizar.

## Segurança

- Leia o [modelo de ameaças](docs/threat-model.md): um operador malicioso tem o mesmo poder que um
  miblo.ai malicioso, que o protocolo já tolera.
- Uma conta só, segundo fator obrigatório; a senha sozinha nunca entra. Senha com PBKDF2-SHA-256
  (600.000 iterações no Node; 100.000 na Cloudflare, o máximo que um Worker permite). Senhas erradas
  bloqueiam só a rede de onde vieram, por 15 minutos, com a mesma resposta de um nome errado.
- O plugin fixa a chave de identidade do servidor na primeira vez (TOFU) e exige uma assinatura
  nova dela antes de usar o servidor; se a chave mudar, nada é enviado até você aceitar a nova com
  `miblo server set` (e o código do Miblo).
- Guarde `secrets.json` (ou os segredos do Worker) longe de backups que outros leiam.
- Encontrou uma falha? Abra um aviso de segurança privado no GitHub (Security › Report a
  vulnerability). Não abra issue pública.

## Builds reproduzíveis

O build é determinístico (imagem base fixada por digest, dependências do `package-lock.json`). O
Docker grava `dist/HASHES.txt`: o SHA-256 de cada arquivo servido e do servidor, e um hash do
conjunto (`build …`). Para conferir o que roda:

```sh
docker compose exec relay tail -1 dist/HASHES.txt   # o que está rodando
npm ci && npm run build && npm run hashes | tail -1  # o que este código gera
```

Cada release publica esse hash nas notas da release; os três precisam ser iguais.

## Licença

[AGPL-3.0](LICENSE): quem oferecer este servidor modificado como serviço precisa publicar o código
das modificações. O dono do projeto pode trocar a licença enquanto for o único autor.

---

## English

The phone server of [Miblo](https://miblo.ai), to run on your own host: the session relay, the
account your phones join, the phone registry and the phone app (PWA). It speaks the very protocol
the Miblo plugin and miblo.ai speak, so everything of Miblo+ that goes through the phone
(history, replies, approvals, remote tasks) works here, **free and without a license**, for anyone
who runs their own server.

### Privacy

Miblo is already end-to-end encrypted: the keys are made on your computer, reach each phone sealed
to that phone's own key only after you type, on the computer, the 6-digit code the phone shows, and
the server only relays ciphertext. A malicious server (miblo.ai or this one) reads nothing, cannot
slip a phone of its own in, and cannot act on your computer.

What remains is **the phone app's code**: it is a web page, and whoever serves the page runs code
with the phone's keys. On miblo.ai you trust what miblo.ai serves. **On your own server, the app is
what you built from this source** (or a release whose hashes you checked), served by you. That
removes the trust in the JavaScript miblo.ai serves. Details in the [threat model](docs/threat-model.md).

While your server is set, the plugin sends nothing of the phone companion or the account to
miblo.ai (it still reads its signed update manifest from miblo.ai).

### Quick start (Docker, 3 steps)

You need a machine with Docker, a DNS name pointing at it and ports 80 and 443 open (Caddy gets the
TLS certificate by itself).

1. **Get and configure it**
   ```sh
   git clone https://github.com/marcus-campos/miblo-relay.git && cd miblo-relay/deploy/docker
   cp .env.example .env   # set RELAY_DOMAIN to your domain
   ```
2. **Start it**
   ```sh
   docker compose up -d --build
   docker compose logs relay   # shows the setup token and the server's identity fingerprint
   ```
3. **Create your account**: open `https://your-domain/conta` (or `/en/account`), use the setup
   token, set a password and add a second factor (a passkey, recommended, or an authenticator app).
   Generate the recovery codes.

Without Docker: `npm ci && npm run build && PUBLIC_ORIGIN=https://your-domain node dist/server.mjs`
(Node 22.13+ or 23.4+, which have `node:sqlite`) behind any TLS proxy.

### Deploy to your own Cloudflare

A Worker on **your** Cloudflare account (the free plan is enough for one person), with D1 and
Durable Objects:

```sh
npm ci
cp deploy/cloudflare/wrangler.jsonc.example deploy/cloudflare/wrangler.jsonc
cd deploy/cloudflare
npx wrangler d1 create miblo-relay          # put the database_id in wrangler.jsonc
# in wrangler.jsonc: PUBLIC_ORIGIN = your Worker's (or your domain's) https address
npx wrangler d1 migrations apply miblo-relay --remote
cd ../.. && npm run build:app && npm run cf:secrets   # prints the setup token and the fingerprint
cd deploy/cloudflare && npx wrangler deploy
```

Then step 3 above.

### Point your computer at it

In **your own** terminal (never through an AI agent), with a Miblo plugin that has `miblo server`:

```sh
miblo server set https://your-domain
```

Miblo reads the server's identity key, shows its fingerprint (compare it with the one **your**
server printed: `docker compose logs relay` or `node dist/server.mjs fingerprint`) and asks for the
code on your Miblo's screen. In the Miblo desktop app: **Settings › Phone server**. Switching
unlinks this computer and turns the phone companion off at the old server; then:

```sh
miblo account link   # confirm the code at https://your-domain/plus/link
miblo phone on
```

On the phone, open `https://your-domain/app`, sign in and allow the phone on the computer with the
code it shows. `miblo server` shows where it points; `miblo server reset` goes back to miblo.ai
(also with the Miblo's code).

### Configuration

| Variable | Required | What it is |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | yes | The server's https address, the origin alone (`https://relay.example.com`): the app's origin, the passkeys' relying party, the device-link address. Never taken from a request. |
| `TRUSTED_PROXY` | behind a proxy | Your proxy's addresses or ranges (CIDR), comma-separated (`172.30.247.0/24`). Only for a connection from them is the client address the last `X-Forwarded-For` entry (the one the proxy added). Only a rate-limit key. Never set it without a proxy in front. |
| `RELAY_VAPID_SUBJECT` | no | A contact sent to the push services (`mailto:you@example.com`); defaults to the server's address. |
| `SESSION_SECRET`, `MFA_KEY`, `SERVER_IDENTITY_KEY`, `RELAY_VAPID_PUBLIC_KEY`, `RELAY_VAPID_PRIVATE_KEY`, `SETUP_TOKEN` | no (Node) / yes (Cloudflare) | On Node, the ones you do not set are made once and kept in `secrets.json` (0600), in `$MIBLO_RELAY_SECRETS_DIR`. On Cloudflare, `npm run cf:secrets` makes and stores them all. |
| `MIBLO_RELAY_DATA` | no | The database folder (Docker: `/data`). |
| `MIBLO_RELAY_SECRETS_DIR` | no | Where `secrets.json` lives (default: `MIBLO_RELAY_DATA`; Docker: `/secrets`, a volume of its own, kept out of the database's backups). |
| `PORT`, `HOST` | no | Where Node listens (default `0.0.0.0:8787`). |

Node commands: `node dist/server.mjs check`, `fingerprint`, `setup-token` (a setup token works
for one setup; once used, this command makes a new one, to redo an abandoned setup),
`reset-account` (lost every factor: removes the factors and sessions and makes a new setup token;
computers and phones stay). On Cloudflare, delete the `mfa_*` and `sessions` rows with
`wrangler d1 execute` and set a new token with `npx wrangler secret put SETUP_TOKEN` (a long random
value, like `openssl rand -base64 24`) for the same.

### Upgrading

```sh
git pull && cd deploy/docker && docker compose up -d --build
```

Database migrations run at start (Node). On Cloudflare:
`npx wrangler d1 migrations apply miblo-relay --remote && npm run build:app && npx wrangler deploy`.
Watch the repository's releases (security fixes are marked) and back up the `relay-data` volume
first.

### Security

- Read the [threat model](docs/threat-model.md): a malicious operator is as powerful as a
  malicious miblo.ai, which the protocol already tolerates.
- One account, second factor mandatory; the password alone never signs in. Passwords use
  PBKDF2-SHA-256 (600,000 iterations on Node; 100,000 on Cloudflare, a Worker's maximum). Wrong
  passwords lock only the network they came from, for 15 minutes, with the same answer as a wrong name.
- The plugin pins the server's identity key the first time (TOFU) and asks for a fresh signature
  with it before using the server; if the key changes, nothing is sent until you accept the new one
  with `miblo server set` (and your Miblo's code).
- Keep `secrets.json` (or the Worker's secrets) out of backups others can read.
- Found a vulnerability? Open a private security advisory on GitHub (Security › Report a
  vulnerability), not a public issue.

### Reproducible builds

The build is deterministic (base image pinned by digest, dependencies from `package-lock.json`).
The Docker image holds `dist/HASHES.txt`: the SHA-256 of every file served and of the server, and
one hash of the set (`build …`):

```sh
docker compose exec relay tail -1 dist/HASHES.txt   # what is running
npm ci && npm run build && npm run hashes | tail -1  # what this source builds
```

Every release publishes that hash in its notes; all three must match.

### Development

`npm test` runs the relay suite on both runtimes (workerd through Miniflare, and Node), the API
tests, the Worker test and, with `MIBLO_PLUGIN_DIR` pointing at a Miblo plugin checkout's `plugin/`
folder, an end-to-end test of the real plugin against this server. `npm run typecheck` checks the
types. The phone app under `app/src` is the same source as miblo.ai's phone app; `app/shims` and
`app/src/selfhost` are what this build adds (see [docs/sources.md](docs/sources.md)).

### License

[AGPL-3.0](LICENSE): whoever offers a modified version of this server as a service must publish the
source of their changes. The project owner can change the license while they are its only author.
