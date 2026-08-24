# Segurança

## Princípios

1. Nenhuma sessão pode controlar teclado/mouse antes do estado `authorized`.
2. Conexão assistida exige ação visível do usuário no computador remoto.
3. Acesso não supervisionado é desabilitado por padrão e precisa ser ativado localmente.
4. A senha não é salva em texto puro.
5. O relay deve operar atrás de TLS (`wss://`) em produção.
6. O host mostra indicador visual enquanto uma sessão está ativa.
7. Ao desconectar, o host interrompe captura de tela e rejeita eventos de entrada antigos.

## Senha não supervisionada

O host gera um salt aleatório e deriva um verificador com PBKDF2-HMAC-SHA256. O arquivo local guarda somente:

- salt;
- número de iterações;
- verificador derivado.

No login, o host envia salt, iterações e um nonce. O viewer deriva o mesmo verificador usando a senha fornecida e responde `HMAC(verifier, nonce)`. O host calcula o HMAC esperado e compara em tempo constante.

A senha em si não é enviada ao relay.

## Produção

A V1 protege o canal usando TLS no relay. Para implantação fora de laboratório, a próxima etapa de hardening deve adicionar identidade criptográfica persistente por dispositivo e criptografia ponta a ponta autenticada da sessão, evitando que um relay comprometido consiga observar conteúdo ou executar ataque de intermediação.

## Auditoria planejada

- log local de data/hora e origem de cada conexão;
- rate limit de tentativas de senha;
- bloqueio progressivo após falhas;
- 2FA/TOTP opcional;
- lista de dispositivos confiáveis;
- revogação de chaves;
- assinatura de binários Windows e APK.
