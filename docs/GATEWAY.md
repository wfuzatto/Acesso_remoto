# Gateway público

## Precisamos de IP público?

Para operação confiável pela Internet, sim: use um VPS ou servidor Ubuntu com IPv4 público alcançável. Os computadores Windows e celulares Android NÃO precisam de IP público e podem ficar atrás de NAT/CGNAT.

O gateway executa três funções:

1. **HTTPS/WSS (Caddy)**: canal de sinalização e autenticação.
2. **STUN (Coturn)**: descobre os endereços públicos e tenta formar conexão WebRTC direta entre os dispositivos.
3. **TURN (Coturn)**: retransmite os pacotes quando P2P não funciona, inclusive em CGNAT/NAT simétrico.

## Fluxo de tráfego

```text
Cenário A - P2P disponível
Windows Host <============================> Viewer Windows/Android
             WebRTC DTLS-SRTP direto
       \                 /
        \ sinalização   /
         v             v
          Gateway público

Cenário B - CGNAT/firewall impede P2P
Windows Host <===> Gateway TURN <===> Viewer Windows/Android
```

No cenário A, o gateway não carrega o vídeo depois que a sessão é negociada. No cenário B, a banda de upload/download do gateway passa a limitar a sessão.

## Dimensionamento inicial

Para JPEG legado considere vários Mbit/s por sessão. Com a evolução WebRTC/H.264/AV1, uma sessão de desktop normalmente poderá operar na faixa de centenas de kbit/s a alguns Mbit/s dependendo de resolução, movimento, FPS e qualidade.

Para começar, um VPS com:

- 2 vCPU;
- 2 GB RAM;
- 1 IPv4 público;
- 100 Mbps ou mais;
- boa franquia de transferência;

é suficiente para sinalização e um número pequeno de sessões TURN simultâneas. Para dezenas/centenas de sessões retransmitidas, a capacidade de rede importa mais que CPU.

## DNS

Crie um registro A, por exemplo:

```text
remote.seudominio.com.br -> 203.0.113.10
```

Depois preencha `gateway/.env`:

```env
REMOTE_DOMAIN=remote.seudominio.com.br
PUBLIC_IP=203.0.113.10
TURN_SECRET=<resultado de openssl rand -hex 32>
TURN_MIN_PORT=49160
TURN_MAX_PORT=49200
```

## Portas

No firewall/NAT do gateway libere:

- TCP 80 - ACME/redirect HTTP;
- TCP 443 - HTTPS/WSS;
- UDP 443 - HTTP/3 do Caddy (opcional, mas configurado);
- UDP 3478 - STUN/TURN;
- TCP 3478 - TURN sobre TCP;
- UDP 49160-49200 - portas relay TURN.

Os hosts/clientes normalmente só precisam de conexões de saída; não é necessário abrir portas no roteador de cada cliente.

## Instalação Ubuntu

```bash
git clone https://github.com/wfuzatto/Acesso_remoto.git
cd Acesso_remoto
cp gateway/.env.example gateway/.env
nano gateway/.env
sudo bash gateway/install-ubuntu.sh
```

Valide:

```bash
docker compose --env-file gateway/.env -f gateway/docker-compose.yml ps
curl https://remote.seudominio.com.br/health
```

## IDs persistentes

O relay grava `deviceId -> accessId` no volume Docker `relay-data`. Reiniciar ou atualizar o container não troca o ID de nove dígitos do computador.

## Credenciais TURN

Não existe uma senha TURN fixa embutida no APK/EXE. O servidor gera credenciais temporárias compatíveis com o mecanismo REST do Coturn usando `TURN_SECRET`. A validade atual é de uma hora.

## Próxima camada de endurecimento

- TURN-TLS em TCP 443/5349 para redes corporativas muito restritivas;
- múltiplos gateways regionais;
- health checks e failover DNS;
- métricas Prometheus;
- rate limiting por IP/dispositivo;
- banco transacional quando houver múltiplos nós de sinalização;
- criptografia de identidade de dispositivo e pinning de chave.
