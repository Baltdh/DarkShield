# Bloqueio do DarkShield: diagnóstico pendente da mensagem
Consulta em 28/09/2026. Não há captura do aviso do Google neste material. A imagem recebida mostra gerenciamento de aplicativos, não o bloqueio. Não está comprovado que a causa seja uma conta nova.

## Distinguir as situações
- **Pedido de verificação de um app desconhecido:** não equivale a classificação como malware. A orientação do Google é enviar para a análise oferecida; recurso contra malware não se aplica a esse simples aviso.
- **App bloqueado como nocivo ou por permissões sensíveis:** revisar o APK exato, permissões e funcionamento; se for falso positivo, usar o recurso oficial indicado pelo Google.
- **Rejeição no Play Console:** obter o e-mail e identificador da política. Resolver declarações, privacidade e requisitos específicos; assinar de novo não resolve uma rejeição de política.
- **Verificação de identidade do desenvolvedor:** requer conta e registro no console apropriado. Não pode ser concluída por uma alteração de código.

A página oficial consultada informa 30/09/2026 como próximo marco para lojas participantes no Brasil, Indonésia, Singapura e Tailândia; expansão global para todos os apps em dispositivos certificados em 2027. Portanto não atribuímos automaticamente um bloqueio de APK direto em 28/09 a esse marco futuro.

## Medidas técnicas desta entrega
A versão de teste usa o pacote existente com versão incrementada e a mesma chave de assinatura. A nova tela “Sobre e instalação” gera um diagnóstico local do próprio app para copiar, sem identificadores pessoais. A varredura continua local e a revisão por IA tem consentimento e prévia do conteúdo.

O inventário de aplicativos requer QUERY_ALL_PACKAGES. Para distribuição no Google Play, a elegibilidade de um antivírus não substitui a declaração e revisão dessa permissão. O relatório técnico do APK entregue acompanha este arquivo. Não afirmamos que o Google aprovou a versão.

## Evidência necessária do usuário
Enviar captura integral do aviso, informar de onde foi baixado o APK e, se for Play Console, o texto da rejeição sem dados pessoais. Se conseguir abrir o app, copiar “Mais ferramentas → Sobre e instalação”. Isso permite corrigir a causa real ou preparar o recurso adequado.

## Rotas oficiais
- Tipos de avisos e link de recurso: https://developers.google.com/android/play-protect/warning-dev-guidance
- Verificação e escolha do console: https://developer.android.com/developer-verification
- Política de visibilidade de pacotes: https://support.google.com/googleplay/android-developer/answer/10158779

Não foi desativado nem contornado o Play Protect. Não houve acesso ao console da conta nem envio de recurso em nome do usuário.
