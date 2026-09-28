# DarkShield: estudo de detecção e classificação
Data: 28/09/2026. Separar esta pesquisa documental dos resultados da análise de binários em ANALISE-BINARIA.md.

| Fabricante | Técnica documentada | Aplicação ao DarkShield |
|---|---|---|
| Norton, Android | App Advisor combina reputação em nuvem e critérios de segurança/privacidade; diferencia coleta de dados, riscos potenciais e malware. | Separar acesso sensível de diagnóstico de malware; não chamar permissão de infecção. Reputação exige serviço e dados próprios/licenciados. |
| Avast, arquitetura geral | Camadas de análise estática, correspondência de padrões, aprendizado de máquina, emulação e comportamento. Parte da descrição trata de PE/Windows. | Preservar a origem de cada sinal, correlacionar sinais independentes e explicitar o que não foi observado. Emulação Windows não é recurso disponível a um APK Android comum. |
| Malwarebytes, Android | Varredura de malware e aplicativos potencialmente indesejados, com revisão e ações de remoção/ignorância. | Mostrar evidência e ação de remediação; PUP não deve ser um rótulo baseado apenas em permissões. |
| AVG, console empresarial | Heurística, emulação e configurações de PUP; sensibilidade maior pode aumentar falsos positivos. | Calibrar confiança e medir falsos positivos antes de elevar agressividade. A documentação empresarial não prova implementação idêntica no Android. |

## Implementado em 0.7.5-test
- UNKNOWN não conta mais como evidência forte. Somente observações com impacto positivo, não informativas e sem marcador de lacuna podem elevar esse contador.
- Multiplicação de pontos usa long, evitando overflow e risco negativo em entradas grandes.
- Tipos de achados baseados em campos estruturados: informação, limite, declaração, correlação, vulnerabilidade indicada, acesso sensível, integridade, indicador estático, heurística, revisão.
- Texto alarmante não transforma achado em malware confirmado. Classificação adicionada ao relatório legível e JSON.
- Confiança explicitamente descrita como confiança nos sinais; não é probabilidade calibrada de infecção.
- Diagnóstico local do próprio APK com versão, target SDK, certificado e permissões para investigar distribuição.

A revisão por IA da versão anterior continua opcional e apenas explica os achados. Não constitui motor treinado/validado de detecção, não altera pontuação nem executa remoções. Não foi acrescentado um suposto banco de vírus sem dados confiáveis.

## Próximas etapas técnicas justificadas
1. Corpus Android rotulado, autorizado e separado em treino/validação/teste por família e tempo. Medir precisão, recall e falsos positivos por tipo de sinal.
2. Identidade por hash do APK e certificado, com cache versionado e origem verificável; ausência em uma base não significa benignidade.
3. Reputação opcional com consentimento e contrato de API. Não copiar assinaturas, pesos ou bancos proprietários dos fabricantes.
4. Validar remoção real em aparelhos: aplicativo comum, administrador ativo, aparelho gerenciado, cancelamento e pacote de sistema. Android controla a desinstalação.
5. Adquirir APKs oficiais das mesmas versões e splits, com origem comprovada, para examinar manifestos, DEX e bibliotecas nativas. Os EXEs deste estudo não demonstram implementação Android.

## Fontes oficiais consultadas
- Norton App Advisor: https://support.norton.com/sp/pt/br/home/current/solutions/v20230714121025571
- Avast: https://www.avast.com/en-gb/technology/malware-detection-and-blocking
- Malwarebytes Android: https://help.malwarebytes.com/hc/en-us/articles/31589655613083-Run-a-scan-on-Malwarebytes-for-Android
- AVG: https://businesshelp.avg.com/Content/Products/AVG_Management_Consoles/DeviceManagement/CustomScan.htm
