# Cobertura de ameaças Android do DarkShield

Atualizado em 2026-09-23. Este documento transforma pesquisa defensiva em requisitos verificáveis do produto. O DarkShield identifica sinais e combinações observáveis por um aplicativo Android comum; ele não afirma provar a ausência ou a presença de malware.

## Referências primárias

- MITRE ATT&CK Mobile — matriz Android e técnicas: <https://attack.mitre.org/matrices/mobile/android/>
- MITRE T1407 — Download New Code at Runtime: <https://attack.mitre.org/techniques/T1407/>
- MITRE T1453 — Abuse Accessibility Features: <https://attack.mitre.org/techniques/T1453/>
- MITRE T1513 — Screen Capture: <https://attack.mitre.org/techniques/T1513/>
- MITRE T1517 — Access Notifications: <https://attack.mitre.org/techniques/T1517/>
- Android — MediaProjection: <https://developer.android.com/media/grow/media-projection>
- Android — Tapjacking: <https://developer.android.com/privacy-and-security/risks/tapjacking>
- OWASP MASVS: <https://mas.owasp.org/MASVS/>

## Mapa de cobertura

| Tática ATT&CK Mobile | Cobertura local atual | Limite importante |
|---|---|---|
| Acesso inicial | origem de instalação, assinatura, versão/target SDK, APK base e splits | phishing, exploração remota e cadeia externa não são observáveis só pelo APK instalado |
| Execução | DEX/nativo, payload disfarçado por assinatura, referências a shell e carregadores DEX | não há telemetria de processos nem confirmação de execução em tempo real |
| Persistência | boot, exceção de bateria, serviços, receivers, administrador e acessibilidade | jobs/alarms ativos e persistência de sistema exigem ADB, privilégios ou telemetria adicional |
| Escalada de privilégio | root, test-keys, build debuggable, administrador do dispositivo | um app sem root não enxerga todas as alterações do kernel/sistema |
| Evasão de defesa | instrumentação, payloads disfarçados, código dinâmico + rede, APKs divididos | ofuscação forte e código baixado depois da instalação podem escapar da análise estática |
| Acesso a credenciais | acessibilidade, overlay, teclado ativo/declarado, notificações e autofill declarado | o conteúdo capturado não é lido pelo DarkShield; a análise preserva privacidade |
| Descoberta | inventário, target SDK, componentes, uso, todos os arquivos e postura do sistema | não há inspeção de memória ou de comandos já executados |
| Coleta | SMS, chamadas, contatos, localização, microfone, câmera e MediaProjection declarada | captura efetiva de tela/mídia requer contexto de runtime que o Android restringe |
| Comando e controle | VPN, proxy, acesso remoto nominal, APIs de rede combinadas com carregamento DEX | INTERNET é comum; domínio/IP ou criptografia isolados não são tratados como prova |
| Exfiltração | correlação de dados sensíveis com capacidades privilegiadas | o app não intercepta tráfego nem realiza ataque-in-the-middle |
| Impacto | administrador, instalação de APK, shell, arquivos e SMS | alterações destrutivas não são testadas nem executadas pelo DarkShield |
| Segurança do próprio app | sem INTERNET, backup desativado, toques encobertos filtrados, overlays ocultados em telas de reparo | teste em aparelhos/fabricantes diferentes continua obrigatório |

## Regras de interpretação

1. Declaração não equivale a concessão, e concessão não equivale a abuso.
2. Uma técnica ATT&CK descreve comportamento possível, não um veredito de malware.
3. Sinais comuns recebem nível informativo ou baixo; combinações independentes podem elevar a prioridade.
4. Apps de sistema, acessibilidade legítima, VPN, gravadores de tela, teclados, suporte remoto e ferramentas de desenvolvimento precisam de contexto.
5. Remoção continua usando a confirmação oficial do Android; o DarkShield não ganha privilégios ocultos nem desinstala silenciosamente.

## Melhorias deste ciclo

- identifica declaração de MediaProjection/serviço de captura de tela e explica o consentimento por sessão;
- identifica serviços declarados de notificações, teclado e autofill sem tratá-los como ativos;
- diferencia administrador do dispositivo declarado de administrador realmente ativo;
- correlaciona captura declarada com acesso remoto ou acessibilidade ativa sem elevar a declaração isolada;
- reconhece referências estáticas a carregadores DEX, obtenção de conteúdo pela rede, execução de shell e ponte JavaScript de WebView;
- mantém carregamento dinâmico isolado como informativo e só pontua a combinação carregador + rede de forma heurística;
- preserva limites de tamanho, quantidade e tempo da análise estática.

## Próximas prioridades

1. Persistir um baseline por pacote para alertar mudança inesperada de assinatura, versão ou origem entre varreduras.
2. Importar, com ação explícita do usuário, dados ADB como `dumpsys package`, AppOps e serviços para ampliar a visibilidade sem root.
3. Criar uma base opcional de reputação por SHA-256/assinatura, com consentimento e sem enviar o relatório completo.
4. Migrar compile/target para o SDK estável seguinte após validar AGP, especialmente para proteções Android 16 em conteúdo sensível.
5. Validar instalação, atualização, rolagem, reparo e varredura longa em aparelhos Android reais de fabricantes diferentes.
