# DarkShield — Monitor de continuidade

Atualizado: 2026-09-18 — auditoria contínua / preparação para fechamento

## Estado atual

- Repositório: `Baltdh/DarkShield`
- Branch: `main`
- Último commit de código/testes: `1eaeedf1ca558df0ee5ad002368f51aa1283834b`
- Última execução de CI relevante: run `35323922374` (run 211), associada ao commit acima.
- No momento desta atualização, run 211 está **PENDING**, enquanto o run 210 ainda aparece **IN_PROGRESS** no GitHub Actions; não há resultado final do run 211.
- A atualização deste arquivo não dispara o workflow atual, pois `MONITOR_20MIN.md` não está incluído nos `paths` do gatilho `push`.

## Correções recentes

1. `7d04b8cf3cd40c4df11abb23e6ff6f31ffe0f9c4` — o analisador estático passou a reconhecer payloads executáveis por assinatura, além da extensão/caminho.
   - DEX: `dex\\n`
   - ODEX: `dey\\n`
   - VDEX: `vdex`
   - ELF: `0x7F ELF`
   - Isso permite amostrar, dentro dos limites já existentes, payloads disfarçados como `.bin`/`.dat`.
2. `8a84328531c303558329a83c82229e7f3288fa1a` — regressão determinística para o desempate da correlação de ameaças.
3. `181fc45f4f689116ec813af815cfa53c165fdc3e` — teste do payload ELF disfarçado contendo marcador `frida`.
4. `91230eea853602cb433cad94e8e51f24f98a1406` — análise de postura local:
   - bloqueio de tela seguro;
   - nível do patch de segurança do sistema;
   - refinamento da detecção de Content Provider exportado sem proteção.
5. `a723dfbcf377e537059d8838a6baf1f404894288` + `32552137ef77f1fae0217bbb41d491b2c6243863` + `589681589b888915540e585d86cc1d71df737a25` — testes do provider e correção para deixar a regra independente das classes do framework nos testes JVM.
   - O erro de compilação em `ProviderInfo.permission` foi identificado pelo log do CI e removido.
   - Os testes que instanciavam `ProviderInfo` foram simplificados para a regra pura `exported/readPermission/writePermission`, evitando `RuntimeException` de stubs Android no teste local.

## Evidência dos ciclos anteriores

- Run `35323196746` (run 200): build debug e verificações do APK passaram, mas houve 1 teste falhando em `ThreatCorrelationEngineTest`; posteriormente corrigido.
- Run `35323697715` (run 207): falhou na compilação por referência inexistente a `ProviderInfo.permission`; build e demais etapas foram impedidos. A causa foi corrigida.
- Run `35323791856` (run 209): build passou e 100 testes foram executados; 3 testes falharam porque os novos testes JVM dependiam de `ProviderInfo` do framework. A regra foi redesenhada para testes puros.
- Runs 204–208 foram cancelados pela política de concorrência após novas alterações no `main`; não usar esses runs como evidência final de estado verde.

## CI atual

- Run 214: `35324680484` (commit `1eaeedf1ca558df0ee5ad002368f51aa1283834b`) — pendente no momento da última consulta.
- Run 212: `35324487511` — **SUCCESS**, validando o helper de provider JVM-safe.
- Run 213: `35324667064` — cancelado pela concurrency após o commit seguinte.
- Commit: `589681589b888915540e585d86cc1d71df737a25`
- Estado observado: **PENDING**
- Run 210: `35323919335` no commit `32552137ef77f1fae0217bbb41d491b2c6243863`, ainda reportado pelo GitHub como **IN_PROGRESS**.
- Não declarar o projeto verde até o run 211 terminar e confirmar:
  - build debug;
  - testes unitários;
  - lint;
  - APK não vazio;
  - SHA-256;
  - `zipalign`;
  - `apksigner verify`;
  - upload do APK e do hash.

## Auditoria técnica atual

O DarkShield já verifica, sem exigir root:
- inventário de pacotes;
- permissões/AppOps sensíveis;
- overlay, WRITE_SETTINGS e MANAGE_EXTERNAL_STORAGE;
- microfone/câmera, SMS, chamadas, contatos/localização/estado de telefonia;
- uso de apps;
- solicitação de instalação de APK;
- boot persistence;
- serviços de acessibilidade declarados e ativos;
- listeners de notificações;
- administradores/device owner/profile owner;
- indicadores de acesso remoto;
- componentes exportados e Content Providers;
- VPN e proxy de rede;
- root, test-keys, build debuggable e marcadores de root;
- target SDK antigo, debuggable, testOnly e cleartext;
- certificado SHA-256 do aplicativo;
- análise estática do APK com limites de tamanho/entradas/amostragem;
- marcadores em DEX, bibliotecas e payloads executáveis disfarçados;
- correlação de sinais sem tratar heurística como prova automática de malware.

## Nova etapa — AndroidX Security State

- Adicionado `androidx.security:security-state:1.1.0`.
- O scanner agora consulta, sem rede, os níveis atuais de Sistema, módulos Mainline e Kernel.
- A biblioteca fornece estado de patch granular; isso complementa o `Build.VERSION.SECURITY_PATCH` anterior. citeturn3search0turn3search1
- Não foi adicionada pontuação automática ao SPL: ausência/atraso de patch é contexto de postura, não prova de malware.

## Próxima etapa

1. Esperar o scheduler do GitHub liberar a run 211 sem criar outra alteração de código.
2. Se a run 211 falhar, usar o log concreto e corrigir somente a causa reproduzível.
3. Se ficar verde, registrar os dados finais de APK e CI aqui.
4. Depois disso, continuar o fechamento com:
   - AndroidX Security State 1.1.0 para postura de patch por sistema/Mainline/kernel;
   - endurecimento da cadeia de CI (incluindo pinagem de actions por SHA, se aplicável);
   - eventual fluxo de release assinado separado do debug;
   - revisão final de UX, relatório e limites do scanner.

## Regra do monitor

Não afirmar que foram feitos ciclos síncronos “a cada 20 segundos por 20 minutos” sem evidência real desses ciclos. Registrar apenas verificações efetivamente executadas e resultados observáveis.
