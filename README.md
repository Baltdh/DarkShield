# DarkShield

**Versão atual: 0.7.0**

DarkShield é um auditor local de segurança para Android. O objetivo é reunir indicadores observáveis no próprio dispositivo para ajudar o usuário a revisar configurações, permissões e componentes potencialmente sensíveis.

## O que a versão atual verifica

- permissões sensíveis e o estado operacional de AppOps quando disponível;
- sobreposição de tela;
- câmera e microfone;
- SMS e histórico de chamadas;
- contatos, localização e estado da telefonia;
- acesso aos dados de uso de aplicativos;
- declaração de inicialização automática após o boot;
- solicitação de instalação de APK;
- acesso especial efetivamente concedido para modificar determinadas configurações do sistema (`WRITE_SETTINGS`); uma declaração sem concessão é mantida como informação e não recebe pontuação;
- acesso especial efetivamente concedido a todo o armazenamento em Android 11+ (`MANAGE_EXTERNAL_STORAGE`); uma declaração sem concessão é mantida como informação e não recebe pontuação;
- serviços de acessibilidade declarados e ativos;
- administradores do dispositivo;
- listeners de notificações;
- serviços VPN declarados e transporte VPN ativo;
- ADB e Opções do desenvolvedor;
- indicadores locais de root, builds de teste e builds de desenvolvimento;
- marcadores de gerenciamento de root em caminhos observáveis;
- proxy HTTP/HTTPS observado pela rede;
- origem de instalação conhecida quando o Android a disponibiliza;
- assinatura SHA-256 do(s) certificado(s) do aplicativo, usando o certificado atual quando há rotação e listando múltiplos signatários em ordem determinística;
- análise estática básica da estrutura ZIP de APKs instalados;
- componentes Android exportados e proteção explícita por permissão, incluindo Activities, serviços, receivers e providers; componentes públicos comuns são mantidos como informação, enquanto providers exportados sem `readPermission`/`writePermission` explícitas recebem um alerta pontuado;
- indicadores heurísticos associados a aplicativos de acesso remoto;
- correlação entre sinais do mesmo pacote para destacar combinações que merecem revisão;
- metadados de aplicativos como target SDK muito antigo, `testOnly` e uso permitido de cleartext;
- aplicativo padrão de SMS e aplicativo padrão de chamadas, mantidos como informação de revisão porque podem lidar diretamente com comunicações do dispositivo;
- resumo por pacote com maior severidade, quantidade de achados e pontos brutos para facilitar a revisão.

## Limitações importantes

DarkShield não é um antivírus baseado em assinatura e não pode garantir que um aparelho está livre de malware. Um indicador isolado não prova invasão, stalkerware ou acesso remoto.

A análise estática atual examina a estrutura ZIP, nomes de entradas e amostras limitadas do início e do final do conteúdo de DEX/bibliotecas em busca de marcadores heurísticos; ela não executa o APK e não substitui análise dinâmica, engenharia reversa ou verificação de reputação do arquivo. Marcadores em recursos não executáveis são tratados como informação técnica sem pontuação isolada.

O scanner usa apenas APIs e informações acessíveis a um aplicativo Android sem root. Alguns estados são protegidos pelo sistema operacional e podem aparecer como não disponíveis. Quando a lista de aplicativos não pode ser obtida, a verificação registra explicitamente que o inventário está incompleto em vez de tratar o resultado como uma varredura normal sem aplicativos.

O uso de QUERY_ALL_PACKAGES pode estar sujeito às políticas de distribuição da Google Play. O projeto foi estruturado para auditoria local e pode ser instalado fora da Play Store.

## Como interpretar o relatório

O **score exibido** é uma medida heurística de revisão, não uma probabilidade de malware. O relatório soma os pontos positivos dos achados e aplica uma escala de exibição limitada a 100 (pontos exibidos = mínimo de 100 e pontos brutos × 3). O campo de **pontos brutos** permanece separado para mostrar quando a escala já atingiu o teto.

Os níveis são derivados da severidade dos achados encontrados: `CRITICAL` resulta em **RISCO CRÍTICO**; `HIGH`, em **RISCO ALTO**; `MEDIUM`, em **REVISÃO RECOMENDADA**; `LOW`, em **POUCOS INDICADORES**. Quando existem somente informações técnicas (`INFO`) ou nenhum achado, o estado é **SEM INDICADORES FORTES**.

Achados `INFO` são mantidos como informação técnica e não entram na contagem de itens que exigem revisão. O resumo por pacote mostra a maior severidade observada, a quantidade de achados relevantes e os pontos brutos acumulados; a lista detalhada de revisão não inclui os registros `INFO`.

## Limites de custo da análise estática

Para manter a verificação completa previsível em aparelhos comuns, o analisador estático impõe limites: APKs acima de 200 MiB não são processados pela análise ZIP; a estrutura é limitada a 10.000 entradas; cada DEX/biblioteca tem amostragem de até 2 MiB; e o orçamento combinado de conteúdo amostrado é de até 8 MiB.

Quando o final de uma entrada ZIP comprimida exigiria pular um prefixo descompactado muito grande, a amostragem da cauda é omitida para evitar custo excessivo. Se uma entrada DEX/biblioteca não puder ser lida, o relatório registra explicitamente a amostra indisponível e não interpreta essa falha como ausência de risco. Esses limites podem reduzir a cobertura da análise estática, e por isso seus avisos não devem ser interpretados como prova de segurança ou ausência de malware.

## Compilação

O workflow `android-release-candidate.yml` também permite gerar manualmente um **APK de release sem assinatura** para validar o empacotamento de produção. Esse artefato ainda precisa ser assinado com a chave de distribuição do responsável pelo aplicativo antes de ser publicado ou distribuído como versão final.

Para gerar a versão assinada pelo GitHub Actions, use manualmente o workflow `android-signed-release.yml`. Ele espera quatro Secrets do repositório: `DARKSHIELD_KEYSTORE_BASE64`, `DARKSHIELD_KEYSTORE_PASSWORD`, `DARKSHIELD_KEY_ALIAS` e `DARKSHIELD_KEY_PASSWORD`. O arquivo de keystore nunca deve ser commitado no repositório. A chave de assinatura deve permanecer sob controle do responsável pelo aplicativo; perder essa chave pode impedir atualizações futuras do mesmo aplicativo. O workflow grava a keystore somente em um caminho temporário do runner, assina o APK e valida `zipalign` e `apksigner` antes de publicar o artefato da execução.

No Linux/macOS, a Secret `DARKSHIELD_KEYSTORE_BASE64` pode ser preparada com `base64 -w 0 darkshield-release.keystore` (no macOS, use `base64 darkshield-release.keystore | tr -d '\\n'`). No Windows PowerShell, use `[Convert]::ToBase64String([IO.File]::ReadAllBytes('.\\darkshield-release.keystore'))`. Adicione os quatro valores em **Settings → Secrets and variables → Actions → New repository secret** e então execute o workflow manualmente em **Actions**.

O workflow do GitHub Actions usa JDK 17 e Gradle 8.11.1 para gerar um APK de debug, executar os testes unitários, rodar o Android lint, calcular o SHA-256 do artefato e validar a assinatura do APK com `apksigner verify --verbose`.

Para uma máquina com o Android SDK configurado:

    cd DarkShield
    ./gradlew --no-daemon assembleDebug
    ./gradlew --no-daemon test
    ./gradlew --no-daemon lintDebug

Saída esperada do APK:

    DarkShield/app/build/outputs/apk/debug/app-debug.apk

## Segurança e privacidade

A análise é local. O aplicativo não precisa de uma conta própria nem de um servidor remoto para executar a verificação. O botão de compartilhamento envia o texto do relatório somente quando o usuário escolhe explicitamente um aplicativo de destino no Android.


## Inteligência de ameaças e correção segura

A versão 0.7.0 acrescenta uma camada local de conhecimento de ameaças baseada em pesquisa pública de Android e MITRE ATT&CK Mobile. As correlações podem apresentar técnicas como abuso de acessibilidade (T1453), acesso a notificações (T1517), software de acesso remoto (T1663) e outros contextos relevantes. Esse conhecimento é explicativo: um único sinal não transforma um aplicativo legítimo em malware.

A arquitetura também foi preparada para uma futura fonte de inteligência por hash/assinatura. Não há chave de API, amostras de malware ou feed externo embutidos no APK. Isso evita transformar uma dependência externa em um veredito falso ou vazar dados do dispositivo.

A Central de correções seguras somente abre telas oficiais do Android para revisão pelo usuário. Ela não desinstala aplicativos nem altera configurações silenciosamente.

Fontes de estudo usadas para o modelo:
- MITRE ATT&CK Mobile: técnicas e exemplos de malware Android.
- Google Play Protect: categorias e comportamento de aplicativos potencialmente nocivos.
- MalwareBazaar/abuse.ch: referência para futura integração de inteligência por hash, sujeita aos termos e à autenticação da API.
- Koodous: referência de análise colaborativa de APKs e resultados estáticos/dinâmicos.
