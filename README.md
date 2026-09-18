# DarkShield

**Versão atual: 0.6.2**

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
- serviços de acessibilidade declarados e ativos;
- administradores do dispositivo;
- listeners de notificações;
- serviços VPN declarados e transporte VPN ativo;
- ADB e Opções do desenvolvedor;
- indicadores locais de root, builds de teste e builds de desenvolvimento;
- marcadores de gerenciamento de root em caminhos observáveis;
- proxy HTTP/HTTPS observado pela rede;
- origem de instalação conhecida quando o Android a disponibiliza;
- assinatura SHA-256 do certificado do aplicativo;
- análise estática básica da estrutura ZIP de APKs instalados;
- componentes Android exportados e proteção explícita por permissão, incluindo Activities, serviços, receivers e providers;
- indicadores heurísticos associados a aplicativos de acesso remoto;
- correlação entre sinais do mesmo pacote para destacar combinações que merecem revisão;
- resumo por pacote com maior severidade, quantidade de achados e pontos brutos para facilitar a revisão.

## Limitações importantes

DarkShield não é um antivírus baseado em assinatura e não pode garantir que um aparelho está livre de malware. Um indicador isolado não prova invasão, stalkerware ou acesso remoto.

A análise estática atual examina a estrutura ZIP, nomes de entradas e um prefixo limitado do conteúdo de DEX/bibliotecas em busca de marcadores heurísticos; ela não executa o APK e não substitui análise dinâmica, engenharia reversa ou verificação de reputação do arquivo.

O scanner usa apenas APIs e informações acessíveis a um aplicativo Android sem root. Alguns estados são protegidos pelo sistema operacional e podem aparecer como não disponíveis.

O uso de QUERY_ALL_PACKAGES pode estar sujeito às políticas de distribuição da Google Play. O projeto foi estruturado para auditoria local e pode ser instalado fora da Play Store.

## Compilação

O workflow do GitHub Actions usa JDK 17 e Gradle 8.11.1 para gerar um APK de debug e executar os testes unitários.

Para uma máquina com o Android SDK configurado:

    cd DarkShield
    gradle --no-daemon assembleDebug
    gradle --no-daemon test

Saída esperada do APK:

    DarkShield/app/build/outputs/apk/debug/app-debug.apk

## Segurança e privacidade

A análise é local. O aplicativo não precisa de uma conta própria nem de um servidor remoto para executar a verificação. O botão de compartilhamento envia o texto do relatório somente quando o usuário escolhe explicitamente um aplicativo de destino no Android.
