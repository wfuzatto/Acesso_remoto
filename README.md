# Acesso Remoto

Plataforma própria de acesso remoto para Windows e Android, inspirada no fluxo de ferramentas de suporte remoto, sem copiar marca, identidade visual ou código de terceiros.

## Objetivos da V1

- Windows host: expõe a tela e recebe mouse/teclado.
- Windows viewer: conecta usando um ID numérico.
- Android viewer: conecta ao mesmo host Windows.
- Conexão assistida: o host recebe uma solicitação visível e precisa aceitar ou rejeitar.
- Acesso não supervisionado: opcional, protegido por senha configurada previamente no host.
- Servidor central: registro de dispositivos, sinalização e relay de sessões.
- TLS obrigatório em produção.
- Senhas nunca são armazenadas em texto puro; o host mantém apenas hash derivado com PBKDF2.

## Arquitetura

```text
Windows Host  <---- WSS ---->  Relay/Signaling Server  <---- WSS ----> Windows Viewer
       ^                              ^                                      
       |                              |                                      
       +------------------------------+------------------------- Android Viewer
```

A V1 usa WebSocket com frames JPEG para simplificar a primeira implantação. O protocolo foi isolado para permitir trocar o transporte de vídeo por WebRTC/H.264/AV1 posteriormente sem redesenhar autenticação, IDs ou fluxo de conexão.

## Estrutura

- `server/` - Node.js + TypeScript, registro e relay.
- `windows/RemoteHost/` - agente Windows (.NET 8 WPF).
- `windows/RemoteViewer/` - cliente Windows (.NET 8 WPF).
- `android/` - cliente Android Kotlin/Compose.
- `docs/` - protocolo, segurança e implantação.

## Fluxo de conexão assistida

1. O Host abre conexão com o servidor e recebe um ID numérico persistente.
2. O Viewer informa esse ID.
3. O servidor cria uma sessão e envia `connection.request` ao Host.
4. O Host mostra origem, horário e permissões solicitadas.
5. O usuário aceita ou rejeita.
6. Somente após aceite os frames de tela e eventos de entrada são encaminhados.

## Fluxo não supervisionado

1. O usuário habilita explicitamente a função no Host e define uma senha.
2. O Host salva apenas `salt + PBKDF2-SHA256(password)` no perfil local.
3. O Viewer solicita conexão `unattended`.
4. O Host envia um desafio aleatório.
5. O Viewer deriva a chave da senha e responde ao desafio com HMAC-SHA256.
6. O Host valida localmente e libera a sessão se a resposta estiver correta.

O servidor nunca precisa conhecer a senha de acesso não supervisionado.

## Desenvolvimento

### Servidor

```bash
cd server
npm install
npm run dev
```

### Windows

Requer Windows 10/11 e .NET 8 SDK.

```powershell
dotnet build windows/AcessoRemoto.Windows.sln
```

### Android

Abra `android/` no Android Studio e gere o APK de debug/release.

## Produção

- Coloque o relay atrás de HTTPS/WSS (Caddy, Nginx ou Traefik).
- Não exponha WebSocket sem TLS fora de laboratório.
- Use um domínio próprio e certificado válido.
- Configure `REMOTE_RELAY_PUBLIC_URL` nos clientes.
- Para acesso pela Internet sem abrir portas nos hosts, apenas o servidor relay precisa ser publicamente acessível.

## Roadmap

- WebRTC P2P + TURN fallback.
- Captura DXGI/Desktop Duplication.
- H.264/AV1 com adaptação de bitrate.
- Clipboard bidirecional.
- Transferência de arquivos.
- Vários monitores.
- Áudio remoto.
- Inventário e lista de dispositivos por conta.
- 2FA para acesso não supervisionado.
- Assinatura automática de builds e instalador MSI/MSIX.
