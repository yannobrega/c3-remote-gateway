# C3 Remote Gateway

Serviço intermediário do C3 Protect Remote. Recebe do backend do painel uma
solicitação autenticada, cria tokens descartáveis e publica sessões SSH e
WebFig sem expor as credenciais dos MikroTiks ao navegador.

## Segurança

- A API de criação de sessão exige `Bearer GATEWAY_API_KEY`.
- O token WebSocket possui 256 bits, expira rapidamente e só pode ser usado uma vez.
- A senha SSH permanece somente na memória até o token ser consumido ou expirar.
- O navegador recebe o token, mas nunca recebe usuário ou senha da RB.
- Somente redes e portas configuradas podem ser acessadas.
- Diagnósticos aceitam somente uma lista fixa de comandos RouterOS v7.
- A origem do WebSocket é validada.
- O WebFig utiliza uma sessão HTTP segura, curta e vinculada a cookie HttpOnly.
- O proxy injeta a credencial somente no salto privado até o RouterOS.
- Logs de auditoria não incluem senha, chave da API ou token de sessão.

## EasyPanel

Crie uma aplicação apontando para este projeto e utilize o `Dockerfile` da raiz.
Configure os domínios `remote.c3protect.com.br` e `webfig.c3protect.com.br`,
ambos apontando para a porta interna `3000` com HTTPS.

Variáveis obrigatórias:

```env
PORT=3000
PUBLIC_BASE_URL=https://remote.c3protect.com.br
WEBFIG_PUBLIC_BASE_URL=https://webfig.c3protect.com.br
WEBFIG_RETURN_URL=https://c3-protect-remote.yan-nobrega.chatgpt.site
GATEWAY_API_KEY=<chave aleatória com no mínimo 32 caracteres>
ALLOWED_ORIGINS=https://c3-protect-remote.yan-nobrega.chatgpt.site
ALLOWED_SSH_CIDRS=172.18.18.0/24,172.17.17.0/24
ALLOWED_SSH_PORTS=22333
ALLOWED_WEBFIG_PORTS=1080
SSH_TARGET_TRANSLATIONS=172.18.18.0/24=192.0.2.0/24,172.17.17.0/24=192.0.3.0/24
SESSION_TOKEN_TTL_SECONDS=60
SSH_CONNECT_TIMEOUT_SECONDS=10
SSH_COMMAND_TIMEOUT_SECONDS=12
SSH_COMMAND_MAX_OUTPUT_BYTES=262144
PROBE_TIMEOUT_SECONDS=3
PROBE_CONCURRENCY=20
MAX_PROBE_TARGETS=250
SSH_SESSION_MAX_SECONDS=7200
WEBSOCKET_HEARTBEAT_SECONDS=20
WEBFIG_SESSION_TTL_MINUTES=30
WEBFIG_UPSTREAM_TIMEOUT_SECONDS=30
MAX_PENDING_SESSIONS=100
MAX_ACTIVE_SESSIONS=20
MAX_PENDING_WEBFIG_SESSIONS=100
MAX_ACTIVE_WEBFIG_SESSIONS=20
```

O container não precisa executar o WireGuard. O host da VPS já possui a rota e
o Docker utilizará o encaminhamento do próprio host para alcançar as redes SSTP.

### Tradução para redes sobrepostas

O `docker_gwbridge` do EasyPanel pode utilizar `172.18.0.0/16`, sobrepondo a
rede SSTP. `SSH_TARGET_TRANSLATIONS` converte somente o destino da conexão do
Gateway para uma faixa virtual. O IP real continua armazenado e exibido no
painel. A VPS deve aplicar `NETMAP` da faixa virtual para a faixa SSTP real.

## API

### `GET /health`

Retorna a saúde do serviço e a quantidade de sessões pendentes/ativas.

### `POST /v1/probes`

Verifica em lote se a porta SSH de cada MikroTik está alcançável. O Gateway
aplica a mesma lista de redes, portas permitidas e tradução de destino usada
nas sessões SSH. A checagem TCP confirma não apenas que o IP responde, mas que
o serviço usado pelo acesso remoto está disponível.

```json
{
  "targets": [
    { "id": "1", "host": "172.18.18.209", "port": 22333 }
  ]
}
```

### `POST /v1/sessions`

Chamado exclusivamente pelo backend do painel:

```json
{
  "deviceId": "1",
  "deviceName": "RB-REVITA",
  "host": "172.18.18.209",
  "port": 22333,
  "username": "c3.remote",
  "password": "senha armazenada no painel",
  "actorEmail": "operador@c3support.com.br",
  "cols": 120,
  "rows": 32
}
```

### `POST /v1/commands`

Executa um diagnóstico RouterOS v7 previamente autorizado. O Gateway nunca
aceita texto de comando enviado pelo navegador.

```json
{
  "deviceId": "1",
  "deviceName": "RB-REVITA",
  "host": "172.18.18.209",
  "port": 22333,
  "username": "c3.remote",
  "password": "senha armazenada no painel",
  "actorEmail": "operador@c3support.com.br",
  "commandId": "system-overview"
}
```

### `POST /v1/webfig-sessions`

Cria um link WebFig descartável. Ao abrir o link, o Gateway grava uma sessão
HttpOnly temporária e passa a encaminhar a interface da RB pela porta permitida.

```json
{
  "deviceId": "1",
  "deviceName": "RB-LCA_ETIQUETAS",
  "host": "172.18.18.214",
  "port": 1080,
  "username": "c3.remote",
  "password": "senha armazenada no painel",
  "actorEmail": "operador@c3support.com.br"
}
```

Resposta:

```json
{
  "sessionId": "uuid",
  "token": "token-descartavel",
  "websocketUrl": "wss://remote.c3protect.com.br/v1/terminal",
  "expiresAt": "2026-09-02T18:00:00.000Z"
}
```

### Protocolo WebSocket

O navegador abre o WebSocket enviando os subprotocolos `c3-remote` e o token
descartável. Isso impede que o token apareça na URL e nos logs comuns do proxy:

```js
const socket = new WebSocket(websocketUrl, ["c3-remote", token]);
```

Navegador para Gateway:

```json
{"type":"input","data":"/system resource print\r"}
{"type":"resize","cols":120,"rows":32}
```

Gateway para navegador:

```json
{"type":"status","status":"connecting"}
{"type":"status","status":"connected"}
{"type":"output","data":"..."}
{"type":"error","message":"..."}
```

## Teste local

```bash
npm ci
npm test
npm start
```
