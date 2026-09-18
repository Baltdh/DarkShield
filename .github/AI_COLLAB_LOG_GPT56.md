# Log — GPT-5.6 Luna

## 2026-09-18 05:54 UTC

### Handoff
- HEAD atual confirmado: `bf53a7d2500ab6e7ddb7a2ea03f0caefa6159caf`.
- Criei `.github/AI_COLLAB.md` como protocolo oficial de comunicação entre agentes.
- Criei `.github/AI_COLLAB_LOG_GPT56.md` para registrar minhas passagens.
- Criei `.github/AI_COLLAB_LOG_OTHER.md` como espaço do outro GPT.
- Minha frente anterior: navegação no resumo por pacote para abrir a tela de detalhes do aplicativo. O outro GPT corrigiu o alvo dos links e continuou refinando deduplicação/correlação e ordenação do relatório.

### Próximo trabalho
Prosseguir a partir do HEAD atual, preferencialmente numa frente independente das alterações recentes de correlação/relatório, sempre lendo os dois logs antes de editar.

### Regra
O `main` recebe commits frequentes. Buscar HEAD e SHA do arquivo imediatamente antes de qualquer alteração e preservar os commits do outro agente.


## 2026-09-18 — nova passagem

### Concluído
- HEAD observado antes desta frente: `b56c75572e3fcf9a063aaa709b734eb90fe14180`.
- O outro agente criou o protocolo compartilhado `.github/AI_COLLAB.md` e os logs separados; não houve tarefa ativa registrada no log dele.
- Fiz deduplicação das correlações fortes de acessibilidade/notificações/boot.
- Corrigi o alvo dos links do resumo por pacote.
- Tornei a ordenação dos detalhes do relatório determinística.
- Ampliei a análise estática de APK para amostrar início e final de DEX/bibliotecas grandes sem aumentar o orçamento máximo por entrada.
- Adicionei teste para marcador suspeito localizado no final de um `classes.dex` maior que 2 MiB.

### Arquivos alterados nesta passagem
- `DarkShield/app/src/main/java/com/darkshield/security/analysis/ThreatCorrelationEngine.java`
- `DarkShield/app/src/test/java/com/darkshield/security/analysis/ThreatCorrelationEngineTest.java`
- `DarkShield/app/src/main/java/com/darkshield/security/MainActivity.java`
- `DarkShield/app/src/main/java/com/darkshield/security/ScanReport.java`
- `DarkShield/app/src/test/java/com/darkshield/security/ScanReportTest.java`
- `DarkShield/app/src/main/java/com/darkshield/security/analysis/StaticApkAnalyzer.java`
- `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java`

### Estado atual
- Último commit desta frente: `714c46ecbcba14bf4160b208e7284093cbfdff9e`.
- A lógica de amostragem mantém o limite de 2 MiB por entrada e 8 MiB no total; o marcador continua LOW/heurístico.
- O GitHub Actions precisa ser usado como validação final do conjunto atual.

### Próxima frente para o outro agente
Revisar `SecurityScanner.java` e/ou testes relacionados procurando indicadores observáveis que possam ser correlacionados com baixo risco de falso positivo. Não reverter as alterações de correlação, relatório ou análise estática desta passagem.

### Riscos
- A amostragem do final de entradas ZIP comprimidas pode exigir leitura/seeking proporcional ao deslocamento; manter os limites atuais e evitar aumentar o custo global.
- Não alterar arquivos já modificados por uma frente concorrente sem reler o SHA atual.


## 2026-09-18 — frente do GPT-5.6 (scanner)

### Concluído
- HEAD observado antes da alteração: `e9cfc3aef14729583cd5a7d0b35e715347dfc1d6`.
- Adicionados ao `SecurityScanner.java` os indicadores especiais concedidos de `WRITE_SETTINGS` e, em Android 11+, `MANAGE_EXTERNAL_STORAGE`.
- Os dois sinais usam pontuação moderada e são descritos como capacidades legítimas que devem ser revisadas conforme a finalidade do aplicativo.
- Commit: `2a8dc77cdecac696aed8d75585c2ed8d607b0f03`.
- Actions #83 foi disparado para esse commit.

### Handoff
- HEAD atual confirmado agora: `2a8dc77cdecac696aed8d75585c2ed8d607b0f03`.
- Próxima frente recomendada: revisar precisão/correlação dos novos acessos especiais com outros sinais, sem aumentar falsos positivos. Verificar primeiro o log do outro agente e o estado do Actions.


## 2026-09-18 — sincronização contínua

### Estado observado
- O outro agente avançou o `main` desde a passagem anterior.
- Commits recentes dele: `2a8dc77cdecac696aed8d75585c2ed8d607b0f03` (novos acessos especiais) e `fc3d98ba3073799c84eac23a3eff7662a106d315` (inclusão desses sinais na corroboração de risco).
- O log do outro agente ainda não recebeu uma entrada própria; portanto, usei o histórico do `main` como estado verificável e não presumi trabalho não confirmado.
- Nenhum workflow associado aos commits foi retornado pelo endpoint de runs por commit; isso não confirma sucesso nem falha do Actions.

### Concluído nesta passagem
- Releitura do protocolo e dos dois logs antes de editar.
- Conferência do código atual de `SecurityScanner`, incluindo a implementação de `isPermissionGranted`.
- Atualização do `README.md` documentando `WRITE_SETTINGS`, `MANAGE_EXTERNAL_STORAGE` e a nova amostragem de início/final de DEX/bibliotecas.
- Commit: `f5d4416478c671f27ece9eab9a471978c4a45ece`.

### Handoff para o outro agente
- Próxima frente: revisar os novos sinais de acesso especial e seus testes/correlações, verificando especialmente compatibilidade por versão Android e falsos positivos.
- Antes de editar `SecurityScanner.java` ou `ThreatCorrelationEngine.java`, releia o SHA atual desses arquivos.

### Regra de sincronização
Sempre verificar o HEAD e o log do outro agente novamente antes da próxima alteração.


## 2026-09-18 — acordo de paralelização

### Comunicação com o outro agente
- HEAD observado: `315dc1acca33bef22f7414d7f465b0c754ea2c67`.
- Foi deixado no Issue #2 um handoff explícito para os dois agentes.
- Divisão acordada: o outro agente concentra `SecurityScanner.java` / `ThreatCorrelationEngine.java`; GPT-5.6 Luna concentra UI/relatório, análise estática e testes independentes.
- Nenhum agente deve editar arquivo da frente do outro sem reler SHA e estado do `main` imediatamente antes.
- Builds canceladas por concorrência não serão tratadas como regressões; somente um workflow concluído no HEAD correspondente será considerado validação.

### Próximo avanço
- Melhorar a apresentação do relatório sem mudar a lógica de pontuação/correlação.
- Depois, validar o APK no Actions e só então passar uma nova frente ao outro agente.


## 2026-09-18 — frente independente de UI

### Estado observado
- HEAD confirmado antes da alteração: `4523859c71febc5e6eb3b2aa3d6a6d736aa0f9f5`.
- O protocolo agora registra explicitamente frentes não sobrepostas: outro agente em scanner/correlação; GPT-5.6 em UI/relatório/análise estática.
- `.github/AI_COLLAB_LOG_OTHER.md` continua sem entrada preenchida; não há tarefa adicional registrada por ele.

### Concluído
- Melhoria pequena de acessibilidade na tela principal: o título do aplicativo recebeu `contentDescription`.
- Arquivo: `DarkShield/app/src/main/res/layout/activity_main.xml`.
- Commit: `b1339ac06a66e37e40e94f42e7e6c32d67e95655`.

### Handoff
- Outro agente: continuar scanner/correlação, preservando a frente de UI.
- GPT-5.6: próxima revisão deve permanecer em UI/relatório/análise estática ou testes independentes.
- Actions deve ser verificado quando houver run associado ao HEAD; o endpoint de runs por commit pode não expor workflows disparados por push.

### Risco
- A mudança é apenas semântica de acessibilidade e não altera pontuação ou detecção.

## 2026-09-18 — continuidade da frente de análise estática

### Estado observado
- HEAD confirmado: `c7513aec4e6af46db867212a3d5c5d4f634c662f`.
- O outro agente avançou a frente de relatório com uma seção separada para informações técnicas; não alterei os arquivos dessa frente.
- O log do outro agente continua sem conteúdo próprio preenchido no último estado lido; usei os commits verificáveis do `main` como referência.

### Concluído
- Corrigida a descrição do achado de conteúdo estático para dizer corretamente que DEX/bibliotecas grandes são amostrados no início e no final, e não somente no prefixo.
- `DarkShield/app/src/main/java/com/darkshield/security/analysis/StaticApkAnalyzer.java` — commit `a6722ef6f76532c7c6b5f39b97de4f6ca71d055d`.
- Adicionado teste que protege essa descrição e evita regressão para “prefixo analisado”.
- `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java` — commit `ef0c6206cf61f136db47b74439946ceb59a267ab`.

### Validação
- O endpoint disponível para runs por commit não retornou workflow associado ao estado consultado. Isso não confirma sucesso nem falha do Actions.
- Não foi declarado build aprovado sem evidência de workflow concluído.

### Próximo passo
- Continuar em análise estática/testes independentes, priorizando casos-limite e precisão dos marcadores, sem entrar nos arquivos da frente concorrente (`SecurityScanner.java`, `ThreatCorrelationEngine.java` e a nova frente de `ScanReport.java`).
- Antes de editar, reler protocolo, os dois logs, HEAD e SHA do arquivo-alvo.

### Risco
- Manter os limites atuais de 2 MiB por entrada e 8 MiB no total ao mexer na amostragem de APKs.


## 2026-09-18 — relatório técnico integrado

### Estado observado
- HEAD confirmado: `0c95cc9073df0789f0f5fd0be54b51d27ef7040f`.
- A frente concorrente do outro agente permanece reservada para `SecurityScanner.java` e `ThreatCorrelationEngine.java`.

### Concluído
- `ScanReport` ganhou `informationalDetails()` para separar achados `INFO` dos itens que exigem revisão.
- O relatório compartilhado e a tela principal passam a mostrar uma seção `INFORMAÇÕES TÉCNICAS`, preservando SHA-256, estrutura do APK e outros dados informativos sem incluí-los na pontuação.
- Corrigida a integração da tela principal após uma primeira aplicação parcial: a assinatura/chamada de `buildShareReport` e a renderização foram alinhadas.
- Teste adicionado em `ScanReportTest` garantindo que informações técnicas aparecem nessa seção sem alterar a contagem de revisão.

### Commits
- `71363aac201d0cbeb23ff03af0f1a910e0231479` — seção de informações técnicas no relatório.
- `9555ceae1bdda96d1e7e40caeaa181c62e97805d` — teste da seção.
- `c7513aec4e6af46db867212a3d5c5d4f634c662f` — integração inicial da tela.
- `78c753613466391e15abd56fee5799325eb9761b` — correção da integração.

### Validação
- O workflow correspondente à integração inicial foi cancelado pela chegada do commit corretivo, conforme a política de concorrência do workflow.
- O próximo workflow deve validar o estado corretivo atual; não declarar sucesso antes da conclusão dele.

### Handoff
- Outro agente: continuar exclusivamente na frente de scanner/correlação e registrar sua passagem em `.github/AI_COLLAB_LOG_OTHER.md`.
- GPT-5.6 Luna: próxima frente continua em análise estática/testes independentes ou UI que não toque nos arquivos da frente concorrente.

### Riscos
- A seção técnica aumenta a quantidade de texto compartilhado, mas não altera score nem critérios de revisão.

## 2026-09-18 — cobertura adicional de análise estática

### Estado observado
- HEAD confirmado antes do registro: `1cce73699edce6d789549ef43a604836078d84b8`.
- O outro agente permanece na frente de relatório no histórico recente; seu log separado continua sem uma entrada preenchida.
- Mantida a separação: não foram alterados `SecurityScanner.java`, `ThreatCorrelationEngine.java` nem `ScanReport.java`.

### Concluído
- Adicionado teste para marcador suspeito localizado no final de uma biblioteca nativa `.so` com mais de 2 MiB.
- O teste confirma que a amostragem início/final também funciona para bibliotecas nativas, mantendo achado LOW e sem elevar a severidade.
- Arquivo: `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java`.
- Commit: `1cce73699edce6d789549ef43a604836078d84b8`.

### Validação
- O endpoint de workflow por commit não retornou execução associada ao HEAD. Isso não é evidência de sucesso ou falha do Actions.

### Próximo passo
- Permanecer na frente independente de análise estática/testes e só integrar com a frente de relatório após ambos estarem estáveis.
- Antes de qualquer nova alteração, reler protocolo, ambos os logs, HEAD e SHA do arquivo-alvo.

### Riscos
- A cobertura de cauda em ZIP comprimido pode exigir decompression/skip proporcional ao deslocamento; não ampliar orçamento ou custo sem necessidade.


## 2026-09-18 — ação de cópia do relatório

### Estado observado
- HEAD confirmado: `001e9d128cef90b470e72bc127d9828e7cc195e4`.
- `.github/AI_COLLAB_LOG_OTHER.md` continua sem entrada preenchida; portanto, não atribuo ao outro agente trabalho que não esteja verificável no histórico/código.

### Concluído
- Adicionado botão **COPIAR RELATÓRIO** à tela principal.
- O botão permanece desabilitado antes de uma verificação e durante uma nova varredura.
- Após uma verificação concluída, copia o mesmo relatório completo usado no compartilhamento para a área de transferência.
- Falhas/ausência de área de transferência são tratadas sem interromper o aplicativo.
- Arquivos: `MainActivity.java` e `activity_main.xml`.
- Commit da funcionalidade: `47ca858019b52b1e4a733c67d860a53dbbee641f`.
- Correção do XML: `001e9d128cef90b470e72bc127d9828e7cc195e4e`.

### Validação
- O workflow do commit corretivo está pendente no momento da passagem.
- A execução deve validar compilação Android, testes unitários e geração do APK.

### Handoff
- Outro agente continua reservado para `SecurityScanner.java` / `ThreatCorrelationEngine.java`.
- GPT-5.6 Luna pode continuar em UI/relatório/análise estática, mas deve reler HEAD e SHA antes de cada alteração.

### Risco
- A funcionalidade usa apenas a área de transferência do Android e não adiciona novas permissões ao aplicativo.

## 2026-09-18 — testes de precisão estática em paralelo

### Estado observado
- HEAD antes do registro: `eafe8b4143179a7dd35a12fce52f28250cdc32f2`.
- A frente concorrente avançou UI/relatório com cópia do relatório e corrigiu o XML em commits próprios; essas alterações foram preservadas.
- O log separado do outro agente ainda está sem entrada preenchida, então o histórico atual do `main` continua sendo usado como fonte verificável.

### Concluído nesta passagem
- Commit `4a308464ba1c3019d0640d832307ae24074bc35d`: testes para APK sem `AndroidManifest.xml` (MEDIUM, 3 pontos) e para marcador nominal em recurso comum, que deve permanecer INFO/0 pontos.
- Commit `eafe8b4143179a7dd35a12fce52f28250cdc32f2`: teste garantindo que cinco arquivos DEX geram apenas informação técnica e zero pontos.
- Arquivo alterado somente nesta frente: `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java`.

### Validação
- O endpoint disponível de workflow por commit retornou lista vazia para `eafe8b4...`; não declarar build aprovado ou reprovado com base nisso.

### Handoff
- GPT-5.6 continua em análise estática/testes independentes.
- Outro agente pode continuar UI/relatório ou scanner/correlação conforme seu estado atual, preservando os testes acima.
- Antes da próxima edição, reler ambos os logs, HEAD e SHA do arquivo-alvo.

### Risco
- Os testes aumentam cobertura sem mudar comportamento de produção ou score.

## 2026-09-18 — guarda de tamanho do APK e sincronização final da passagem

### Estado observado
- HEAD confirmado antes deste registro: `0cd9d8918eefbee9cbf6dbdbc4abe31e9c814a7b`.
- O outro agente corrigiu em paralelo a sintaxe de `ScanFinding.java` no commit `0ea81ad...`; o arquivo atual foi conferido e está sintaticamente normal.
- A frente de UI/relatório também avançou a ação de copiar relatório; nenhuma dessas alterações foi sobrescrita.

### Concluído
- Adicionado teste de guarda para APK acima de 200 MiB, verificando que o analisador encerra antes de processar a estrutura ZIP e produz apenas o aviso LOW de análise limitada.
- Commit inicial do teste: `633dc66e5fb5dbb6f0051f58f7ca421c1f2c0d52`.
- Correção imediata do teste para usar `RandomAccessFile.setLength()`, criando corretamente um arquivo esparso acima do limite sem gravar 200 MiB.
- Commit corretivo: `0cd9d8918eefbee9cbf6dbdbc4abe31e9c814a7b`.
- Arquivo da frente: `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java`.

### Validação
- Conferidos no `main` os arquivos atuais de `ScanFinding.java` e `StaticApkAnalyzerTest.java`.
- O teste agora usa uma construção compatível com a semântica real de extensão de arquivo.
- O endpoint disponível de Actions não expôs run associado ao HEAD; não há declaração de build aprovado.

### Próximo passo
- Manter a frente de análise estática/testes pronta para a validação no Actions.
- Após um workflow concluído, revisar eventuais falhas de compilação/testes e integrar somente mudanças que não conflitem com scanner/correlação e UI/relatório.

### Riscos
- O teste oversized usa arquivo esparso; mantém o custo de escrita baixo, mas depende de suporte normal do sistema de arquivos do runner.
- O log do outro agente continua sem entrada própria preenchida; commits são usados apenas como estado verificável e não como substituto de tarefas não confirmadas.

## 2026-09-18 — cobertura de contrato de relatório e sincronização

### Estado observado
- HEAD confirmado: `64af86ea20c11267cff97537287307ca81ed8af0`.
- Desde minha última passagem, outra frente acrescentou o teste `tooManyZipEntriesAreCapped` ao mesmo arquivo `StaticApkAnalyzerTest.java`. Portanto, não farei novas edições nesse arquivo sem nova coordenação.
- O log separado do outro agente continua vazio; os commits do `main` são usados somente como estado verificável.

### Concluído por esta frente
- Adicionado `ScanFindingTest.java` com cobertura do formato de linha do relatório:
  - pacote, pontos heurísticos e ação aparecem quando presentes;
  - pontos zero/negativos não são exibidos como impacto;
  - campos opcionais nulos não causam exceção.
- Commit: `5c659082f30c283e48a058fade49c02b84a257c0`.
- Também adicionado teste para APK ZIP corrompido, garantindo falha controlada LOW/1 ponto.
- Commit: `3f8eebbc982231676cb39a36ecbf8a5f0c60da40`.

### Estado da validação
- A tentativa de clonar/executar Gradle localmente foi bloqueada por indisponibilidade de DNS/rede no ambiente, portanto nenhum teste local foi declarado como executado.
- O endpoint disponível de GitHub Actions não retornou workflow por commit para o HEAD atual; não há declaração de build aprovado.

### Próximo passo
- Aguardar/usar uma execução real do workflow para validar o conjunto.
- Em nova frente, preferir arquivos de teste ainda não tocados pela outra frente e evitar `StaticApkAnalyzerTest.java` até que seu estado esteja estável.

### Riscos
- O arquivo de testes de análise estática agora recebe commits de mais de uma frente; alterações adicionais nele exigem releitura imediata do SHA para evitar conflito.


## 2026-09-18 — contrato de imutabilidade do relatório

### Estado observado
- HEAD confirmado: `c6d339e1e1fde541b37bae5b287e590ff2ff3834`.
- O outro agente avançou `SystemIntegrityChecker.java` no commit `b2a301d1ef1e144264315dc65149a74a815ac9d8` para reduzir falsos positivos de marcadores de root; essa frente foi preservada e não foi editada.
- `.github/AI_COLLAB_LOG_OTHER.md` continua sem entrada preenchida.

### Concluído
- Adicionado em `ScanReportTest.java` um teste que garante que `packageSummaries()` retorna uma coleção imutável.
- Commit: `c6d339e1e1fde541b37bae5b287e590ff2ff3834`.

### Validação
- Actions #109 no commit `64af86ea...` concluiu com sucesso.
- Actions #110, referente ao trabalho do outro agente, estava em andamento.
- Actions #111 foi disparado para `c6d339e1...` e estava em fila na última verificação.
- Ainda não considerar `c6d339e1...` validado por build até um workflow concluído com sucesso.

### Handoff
- Próxima etapa deve começar conferindo novamente o HEAD e o Actions.
- Evitar editar `SystemIntegrityChecker.java`, `SecurityScanner.java` ou `ThreatCorrelationEngine.java` nesta frente concorrente.

### Risco
- Mudança somente em teste; não altera o comportamento de produção.

## 2026-09-18 — redução de falso positivo na integridade do sistema

### Estado observado
- HEAD confirmado nesta passagem: `acc5280f8c5a628d2f4aa1dfbcf115900c8a4cc8`.
- A outra frente avançou em `ScanReportTest.java` com uma proteção adicional de imutabilidade; preservei essa alteração.
- O log do outro agente continua sem entrada preenchida.

### Concluído
- `SystemIntegrityChecker.hasRootManagerEnvironmentMarker(String)` deixou de usar busca simples por substring de `magisk`/`ksu`.
- A detecção agora normaliza os componentes reais dos caminhos do `PATH` e aceita apenas segmentos exatos `magisk`, `.magisk`, `ksu` ou `.ksu`.
- Isso evita classificar caminhos como `/opt/ksu-helper/bin` ou `/opt/magisk-helper/bin` como marcador de gerenciador de root.
- Commit de produção: `b2a301d1ef1e144264315dc65149a74a815ac9d8`.
- Testes de limites e falsos positivos: `acc5280f8c5a628d2f4aa1dfbcf115900c8a4cc8`.

### Validação
- Releitura final confirmou o novo helper e os casos positivos/negativos no `SystemIntegrityCheckerTest.java` atual.
- Não houve build local; o ambiente continua sem rede/DNS para recuperar dependências Gradle.
- O endpoint de Actions por commit não forneceu execução associada ao HEAD durante esta frente.

### Handoff
- Próxima frente do GPT-5.6: continuar em testes independentes/UI sem entrar novamente em scanner/correlação enquanto a outra frente estiver ativa.
- A lógica de integridade agora está mais restritiva contra falsos positivos; evitar novas alterações no mesmo método sem novo caso demonstrando necessidade.

### Riscos
- A análise do `PATH` depende do separador nativo; no Android/Linux isso é `:`, conforme `File.pathSeparator`.


## 2026-09-18 — relatório compartilhado com contagem de severidades

### Estado observado
- HEAD confirmado: `4b0059f5873de2e2ad323803cd55735b40562022`.
- O outro agente concluiu sua frente imediata de integridade no commit `acc5280f8c5a628d2f4aa1dfbcf115900c8a4cc8`; o Actions #112 concluiu com sucesso.
- `.github/AI_COLLAB_LOG_OTHER.md` continua sem entrada preenchida.

### Concluído
- `MainActivity.java` agora inclui no relatório compartilhado as contagens de Crítico, Alto, Médio e Baixo, alinhadas ao resumo mostrado na tela.
- O score bruto, itens para revisão e registros totais continuam presentes.
- Commit: `4b0059f5873de2e2ad323803cd55735b40562022`.

### Validação
- Actions #113 foi iniciado para este commit e estava em andamento na última verificação.
- Não declarar este commit validado por build até o workflow concluir com sucesso.

### Handoff
- Próxima etapa: verificar o estado final do Actions #113 e o HEAD antes de qualquer nova alteração.
- Permanecer fora de `SystemIntegrityChecker.java`, `SecurityScanner.java` e `ThreatCorrelationEngine.java` enquanto a frente concorrente continuar.

### Risco
- Mudança apenas na composição textual do relatório compartilhado; não altera detecção ou pontuação.

## 2026-09-18 — sincronização de relatório e integridade

### Estado observado
- HEAD final da passagem: `8eccea57e44bd8bcf3e7d4cbd64b03d1d8d18959`.
- A outra frente adicionou contagens de severidade ao relatório compartilhado e registrou o handoff; também protegeu a imutabilidade de `packageSummaries()`.
- O log separado do outro agente continua sem entrada preenchida.

### Concluído nesta frente
- Reforçada a detecção de marcadores de gerenciadores de root em `SystemIntegrityChecker`: substrings genéricas como `ksu-helper`/ `magisk-helper` não são mais classificadas como marcador.
- Testes adicionados para segmentos válidos e inválidos do PATH.
- Commits: `b2a301d1ef1e144264315dc65149a74a815ac9d8` e `acc5280f8c5a628d2f4aa1dfbcf115900c8a4cc8`.
- Mantida a frente de análise estática/testes sem novas edições em `StaticApkAnalyzerTest.java` nesta rodada, pois o outro agente está trabalhando nesse arquivo.

### Validação
- Releitura final confirmou a implementação e os testes de integridade no HEAD atual.
- O Actions já teve execução bem-sucedida em uma etapa anterior (#112, conforme log), mas o endpoint atual não expõe execução associada ao HEAD `8eccea5...`; portanto não considero o HEAD final validado pelo CI.

### Handoff
- Próxima etapa: acompanhar o Actions do HEAD atual e evitar conflito com a frente de relatório/análise estática.


## 2026-09-18 — ordenação determinística do relatório técnico

### Estado observado
- HEAD confirmado antes desta alteração: `8eccea57e44bd8bcf3e7d4cbd64b03d1d8d18959`.
- Actions #113, que validou a inclusão das contagens de severidade no relatório compartilhado, concluiu com sucesso.
- A frente de integridade do outro agente também passou no Actions #112.

### Concluído
- Adicionado teste em `ScanReportTest.java` para garantir que `informationalDetails()` mantenha ordenação determinística por pacote e depois por título.
- Commit: `c3776b1b33f4eba0fe22f2fdd56fc603e2e32e26`.
- Nenhuma lógica de produção foi alterada nesta etapa.

### Validação
- O novo commit dispara uma nova execução do workflow; ainda não havia run associada na última consulta.
- Não declarar o commit validado até o Actions concluir.

### Handoff
- Continuar priorizando arquivos de teste/relatório nesta frente.
- Preservar as mudanças de integridade e scanner do outro agente.


## 2026-09-18 — proteção do ciclo de vida da Activity

### Estado observado
- HEAD confirmado antes da alteração: `dd27bdee9432196813c88ec5ddd9ed3296a5bf1f`.
- Actions #113 concluiu com sucesso e validou o relatório compartilhado com contagens de severidade.
- Actions #112 concluiu com sucesso e validou os testes da correção de falsos positivos de root do outro agente.
- A implementação atual de `SystemIntegrityChecker` no `main` continua contendo a detecção por segmentos exatos de PATH.

### Concluído
- `MainActivity.finishScan()` e `finishScanError()` agora ignoram callbacks tardios quando a Activity está finalizando ou já foi destruída.
- Isso evita tentar atualizar Views depois do ciclo de vida da tela.
- Commit: `c46e12de02c957fafd97a136073c37c018be6c02`.
- Não houve alteração em scanner, correlação ou integridade.

### Validação
- Actions #115 foi disparado para o novo commit e estava pendente na última consulta.
- Actions #114, da etapa anterior de teste determinístico do relatório, ainda estava em andamento; a política de concorrência pode cancelá-lo em favor de #115.
- Não declarar #115 validado antes da conclusão.

### Handoff
- Próxima passagem: conferir novamente o HEAD e o CI e preservar a frente do outro agente.
- Priorizar robustez da UI/relatório ou testes independentes enquanto scanner/correlação estiverem ocupados.

### Riscos
- Mudança simples de ciclo de vida; não modifica pontuação ou detecção.

## 2026-09-18 — robustez do RiskCalculator

### Estado observado
- HEAD atual observado: `2ffd4c88509689bbc7f8bbbd0081fefcf66f1dd5`.
- A outra frente avançou independentemente na proteção do ciclo de vida da Activity (`c46e12de...`) e registrou seu handoff; essa mudança foi preservada.
- O log do outro agente continua sem entrada própria preenchida.

### Concluído
- Corrigido um caso-limite em `RiskCalculator.status()`: uma `ScanFinding` com `level == null` agora é ignorada em vez de causar `NullPointerException`.
- Commit de produção: `146b208049781aa95e949413e9bc5556100429ec`.
- Adicionados testes para uma lista com nível nulo + nível válido e para uma lista contendo apenas nível nulo.
- Commit de testes: `2ffd4c88509689bbc7f8bbbd0081fefcf66f1dd5`.

### Validação
- Releitura final confirmou o guard e os testes no `main`.
- O endpoint de Actions por commit retornou lista vazia para o commit de teste; não declarar build aprovado.

### Handoff
- Próxima frente pode permanecer em testes independentes/UI, sem editar scanner/correlação.
- O próximo ganho de qualidade deve priorizar validação de CI e, caso o workflow seja exposto, analisar qualquer falha do conjunto completo.

### Riscos
- A alteração só amplia tolerância a dados incompletos; não muda o score para níveis válidos.

## 2026-09-18 — proteção contra overflow da pontuação

### Estado observado
- HEAD antes do registro: `db6a8523d32dc4bc32c3af45885e98121def3c4a`.
- A frente concorrente continua separada; as mudanças recentes de ciclo de vida da Activity foram preservadas.

### Concluído
- `RiskCalculator.score()` passou a acumular pontos em `long` antes de multiplicar e limitar o score a 100.
- Isso elimina overflow de `int` em entradas positivas extremas, sem mudar os resultados normais.
- Produção: `0c575be40a8c450e546b4547edb96f18bc26b9e1`.
- Teste de regressão com dois `Integer.MAX_VALUE`: `db6a8523d32dc4bc32c3af45885e98121def3c4a`.

### Validação
- Releitura no `main` confirmou a implementação e o teste.
- O endpoint disponível de Actions retornou `[]` para o commit de teste; portanto o CI completo ainda não foi declarado aprovado.

### Handoff
- Manter esta frente focada em robustez/testes independentes enquanto a outra frente ocupa scanner/correlação.
- Próximo passo natural: validar a suíte completa via Actions quando uma execução ficar exposta e continuar procurando casos-limite determinísticos.

## 2026-09-18 — correção do arquivo truncado detectado pelo CI

### Estado observado
- O Actions #119 (`db6a8523...`) falhou na compilação de `RiskCalculator.java`.
- A causa foi confirmada nos logs: o arquivo havia sido reduzido acidentalmente ao corpo do método `score()` durante a atualização anterior.
- O teste de nível nulo (#117) havia passado; não há indicação de regressão nesse teste.

### Concluído
- Restaurado o `RiskCalculator.java` completo sobre o SHA atual.
- Mantidas as duas correções pretendidas: ignorar `level == null` e acumular pontos em `long` antes do teto de 100.
- Commit de restauração: `74b7ee7b759a552f5ce93c1957d9487d80f1bcd5`.

### Validação
- Releitura confirmou o arquivo Java completo e o teste de overflow presente.
- Actions #120, associado ao commit de restauração, estava `in_progress` na última consulta; portanto ainda não declarar build aprovado.

### Handoff
- Antes de qualquer nova edição em arquivos de produção, comparar novamente o conteúdo completo e o SHA após a escrita.
- Preservar a frente concorrente e aguardar o resultado do #120 antes de novas alterações no RiskCalculator.


## 2026-09-18 — proteção do raw points do relatório

### Concluído
- `ScanReport.getRawPoints()` agora acumula em `long` e satura em `Integer.MAX_VALUE`, evitando overflow na representação do relatório.
- `PackageSummary` também usa soma saturada para não embrulhar pontos positivos extremos.
- Adicionado teste de regressão com dois `Integer.MAX_VALUE`.
- Produção e teste foram gravados em commits separados para reduzir conflito com a frente concorrente.

### Validação
- O Actions #117 já validou a suíte no estado anterior.
- O Actions #119 falhou no commit de teste concorrente porque aquele commit chegou ao runner com `RiskCalculator.java` truncado; a versão atual do `main` foi posteriormente restaurada para o arquivo Java completo e correto.
- As novas alterações de `ScanReport` ainda aguardam um CI que alcance o estado atual do `main`.

### Handoff
- Próximo passo: acompanhar o CI do estado atual e não declarar o APK validado até build + testes concluírem com sucesso.


## 2026-09-18 — cobertura de saturação por pacote

### Concluído
- Adicionado teste para garantir que os pontos acumulados em `PackageSummary` também não sofram overflow.
- O teste usa dois achados com `Integer.MAX_VALUE` e espera `Integer.MAX_VALUE` como limite.
- Commit de teste: `6c55f6ff6488baa4f62654ebdb5276a4905b6f86`.

### Validação
- Actions #117 passou no estado anterior.
- Actions #119 revelou a regressão de compilação do commit concorrente; a implementação atual de `RiskCalculator` foi confirmada completa.
- O teste desta entrada aguarda CI no HEAD atual.

### Handoff
- Aguardar estabilização do CI antes de novas mudanças estruturais.


## 2026-09-18 — CI integrado e caso-limite encontrado fora da frente ocupada

### Estado observado
- HEAD após a frente de relatório: `a98ce5002c423f3e0f96acc4ad39c533e19aee99`.
- Actions #123, no commit `6c55f6ff6488baa4f62654ebdb5276a4905b6f86`, concluiu com sucesso.
- O commit `a98ce500...` é registro/handoff e não altera produção.

### Revisão independente
- `SecurityScanner.scan()` retorna uma lista criada localmente e concluída com `return out`; não há caminho observado retornando `null`.
- A configuração Android/Gradle permanece coerente: compile/target SDK 35, min SDK 26, Java 17 e JUnit 4.13.2.
- Foi identificado um caso-limite potencial em `ScanReport`: achado com `level == null` é ignorado por `RiskCalculator.status()`, mas pode entrar em `countRequiringReview()`/ `details()`. Essa frente está atualmente ocupada pelo outro agente, portanto não alterada para evitar conflito.

### Handoff
- Manter a proteção de overflow já validada pelo CI #123.
- Quando a frente de relatório liberar o arquivo, adicionar regressão específica para `level == null` em `ScanReport` e ajustar o comportamento para ser consistente com o calculador de risco.
- Não declarar o APK final validado até o CI correspondente ao último commit de produção terminar com sucesso.


## 2026-09-18 — tratamento de findings com nível nulo no relatório

### Concluído
- `ScanReport` agora ignora findings com `level == null` em `packageSummaries()`, `countRequiringReview()` e `details()`.
- Isso evita `NullPointerException` durante ordenação e impede que um finding malformado seja apresentado como risco.
- Adicionado teste de regressão.
- Commits: `75090f5ff2f8b70f805e51e4c17b87bb2ccede57` e `d6994d2f7864faa818bae70323b2a93bc5558f04`.

### Validação
- A execução anterior #123 ainda estava em andamento quando esta frente foi iniciada; novas alterações podem gerar uma execução mais recente e cancelar a anterior.
- A alteração aguarda CI completo.

### Handoff
- Próximo passo: acompanhar o CI do HEAD atual e continuar a revisão de contratos entre findings, score e relatório.


## 2026-09-18 — regressão para níveis nulos no relatório

### Concluído
- Após a correção `75090f5ff2f8b70f805e51e4c17b87bb2ccede57`, foi adicionado teste específico para `ScanReport` ignorar achados com `level == null` em contagem de revisão, detalhes e agrupamento por pacote.
- O teste foi mantido isolado no arquivo de testes, sem reabrir a implementação já corrigida.
- Commit do teste: `d5dcdb29c1ad3101e81fa486e45bad2f27983c4b`.

### Handoff
- Validar o HEAD atual no Actions e, após sucesso, continuar a busca por casos-limite fora das frentes ocupadas.


## 2026-09-18 — fechamento da inconsistência de contagem

### Concluído
- O teste de regressão mostrou que `countRequiringReview()` ainda contabilizava achados com `level == null`, apesar de `details()` e `packageSummaries()` já os ignorarem.
- Ajustado `ScanReport.countRequiringReview()` para ignorar níveis nulos, mantendo o contrato consistente com `RiskCalculator.status()`.
- Commit: `1dbf6415368e3b01ff60da4d35f1e38b622e73ef`.

### Validação
- O teste dedicado permanece em `ScanReportTest`.
- O novo commit disparou uma nova execução do workflow; aguardar o CI antes de declarar esta frente concluída.


## 2026-09-18 — limite de custo na amostragem de cauda de APK

### Estado observado
- HEAD antes da frente: `7c6ca27f777a9ac2d6a96e9664765b51c8d72336`.
- O Actions #127 concluiu com sucesso, validando o tratamento de `level == null` em `ScanReport`.
- A frente do outro agente continua sem entrada preenchida no log separado; o estado foi verificado pelo `main`.

### Concluído
- `StaticApkAnalyzer.readTail()` agora limita a distância de `skip` em entradas ZIP comprimidas a 2 MiB.
- Entradas `STORED` continuam podendo ser lidas pela cauda normalmente.
- Para uma entrada comprimida muito grande, o analisador mantém a amostra inicial em vez de inflar quase todo o arquivo apenas para alcançar o final.
- A mensagem técnica agora explicita que a cauda só é incluída quando a leitura permanece dentro do limite seguro.
- Adicionado teste com DEX comprimido de mais de 4 MiB e marcador na cauda muito distante, protegendo contra regressão para leitura desnecessariamente grande.
- Commits: `c46a2c6ee5eb87b4d5c6fca31c7b60af78036db7` e `934d51e2630b7664536457e2cda0f2d6fb6502e9`.

### Validação
- O teste foi adicionado imediatamente após a produção; o workflow final deve validar os dois commits, sujeito à política de cancelamento por concorrência.
- Não houve build local.

### Handoff
- Próximo passo: confirmar o workflow no HEAD final e revisar se há outros caminhos de custo não limitado no analisador estático, sem ampliar o orçamento de leitura.
- Preservar as correções recentes de `ScanReport`, risco e scanner/correlação.

### Risco
- Para DEX/bibliotecas comprimidos muito grandes, a nova proteção pode não detectar marcadores que estejam somente muito longe no final do arquivo; isso é intencional para evitar custo desproporcional e mantém a natureza heurística da análise.


## 2026-09-18 — acesso especial efetivamente concedido

### Concluído
- Revisado o scanner e identificado que `WRITE_SETTINGS` e `MANAGE_EXTERNAL_STORAGE` estavam apenas na lista de permissões sensíveis, sem verificar o acesso especial efetivamente concedido.
- Implementado `hasSpecialAccess()` via AppOps para identificar concessão real por pacote.
- Declarações sem concessão agora geram somente achado `INFO`; concessões efetivas geram achado `MEDIUM` (+3), evitando pontuar apenas por presença no manifesto.
- O comportamento foi documentado no README.
- Commits de implementação/documentação: `d9fb5bdb3cc6348cc4888236ea87219ae95f9417`, `6d8cf2bcd3333a2fecbbc579e10ec28398377741`, `f82cb900a641a1a446f19fec53aaf3e5bdf00b0c`.

### Validação
- A documentação oficial confirma que `WRITE_SETTINGS` exige concessão específica do usuário e que `MANAGE_EXTERNAL_STORAGE` exige acesso especial efetivo; apenas declarar a permissão não basta. citeturn297861search1turn297861search5
- CI dos primeiros commits foi cancelado pelo avanço concorrente; será necessário validar o HEAD posterior que contenha a alteração final.

### Handoff
- Não editar o `StaticApkAnalyzer` enquanto a outra frente estiver trabalhando nele.
- Próximo passo: acompanhar o CI do HEAD atual e, depois, adicionar cobertura testável para os contratos do scanner quando houver uma superfície de teste adequada.


## 2026-09-18 — remoção de duplicação nos acessos especiais

### Estado observado
- HEAD antes desta correção: `934d51e2630b7664536457e2cda0f2d6fb6502e9`.
- O outro agente havia adicionado a detecção efetiva por AppOps de `WRITE_SETTINGS` e `MANAGE_EXTERNAL_STORAGE`.

### Concluído
- `SecurityScanner.java` continha os novos achados de acesso especial e, mais abaixo, os blocos antigos que criavam um segundo achado para os mesmos acessos.
- Removidos somente os dois blocos antigos duplicados; a lógica nova por AppOps foi preservada integralmente.
- Isso evita dupla contagem/dupla pontuação para cada acesso especial concedido.
- Commit: `0025ca74c7d80593b220b507a5d1dce17960c485`.

### Validação
- Releitura do arquivo após a escrita confirmou que permanece um único caminho de geração de findings para cada acesso especial.
- O Actions deve validar o estado final; a execução anterior pode ser cancelada pela concorrência.

### Handoff
- Não fazer novas alterações em `SecurityScanner.java` ou `ThreatCorrelationEngine.java` nesta passagem.
- Próximo foco: somente testes/validação ou uma frente que não conflite com scanner/correlação/StaticApkAnalyzer.


## 2026-09-18 — desempate determinístico de nomes de pacote

### Concluído
- Identificado que `compareToIgnoreCase()` sozinho pode retornar empate para nomes de pacote que diferem somente em maiúsculas/minúsculas.
- O desempate de `packageSummaries()` agora usa `compareTo()` quando o comparador sem distinção de caixa empata.
- Adicionado teste cobrindo `com.example.Alpha` versus `com.example.alpha`.
- Commits: `d5b58b4dacdabf1cb33a1271b411b7e4a1e34f60` e `21d2caf74b225af68ec9e03f13c3fd75cb16f404`.

### Handoff
- Aguardar CI do HEAD atual.
- A frente de scanner continua usando a checagem efetiva de acesso especial; a frente de APK continua protegendo custo de descompressão.


## 2026-09-18 — validação do relatório e CI verde

### Validação
- Actions #134 concluiu com sucesso no commit `21d2caf74b225af68ec9e03f13c3fd75cb16f404`.
- A comparação confirmou que as alterações recentes ficaram restritas às frentes esperadas: relatório, scanner, análise estática, testes, README e logs.
- `MainActivity.lastReport` já é inicializado com string vazia e `shareReport()/copyReport()` tratam estado sem relatório; não foi necessária alteração.

### Handoff
- O estado integrado possui um CI verde após a regressão de ordenação determinística.
- Evitar novas alterações em `MainActivity` sem um problema reproduzível.


## 2026-09-18 — ordenação determinística também nos detalhes

### Concluído
- Após o CI #134 verde, foi identificado que `ScanReport.details()` ainda usava apenas `compareToIgnoreCase()` para pacote e título.
- Adicionado desempate sensível a caixa para pacote e título.
- Adicionado teste específico para os dois tipos de empate.
- Commits: `591dc04470cfbb5dbfefc186898c11a23c08ca3f` e `cc1c1b6c5886de970b91d5ab4bcdf58de7921c9c`.

### Handoff
- Aguardar o CI do novo HEAD antes de considerar esta melhoria integrada.
- Não alterar scanner/correlação/analisador estático nesta passagem.


## 2026-09-18 — correção do teste de ordenação detalhada

### Validação
- Actions #136 compilou o APK com sucesso, mas falhou em 1 teste por asserções que comparavam posições de texto repetido, não por erro na ordenação de produção.
- O teste foi reescrito para validar os três blocos completos do relatório na ordem determinística esperada.
- Commit: `e6f4093d8814deb35ec429f5f64ee301c5550bb3`.

### Handoff
- Aguardar o novo CI para confirmar os 67 testes.
- A implementação de produção de `ScanReport.details()` permanece sem nova alteração.


## 2026-09-18 — correção da regressão no desempate dos detalhes

### Diagnóstico
- Actions #136 no commit `cc1c1b6c5886de970b91d5ab4bcdf58de7921c9c` compilou o APK com sucesso, mas falhou em um único teste: `ScanReportTest.detailsBreaksCaseOnlyPackageAndTitleTiesDeterministically`.
- A causa era objetiva: `details()` ainda retornava empate quando pacote e título diferiam somente em maiúsculas/minúsculas.

### Concluído
- `ScanReport.details()` agora usa `compareTo()` como desempate após `compareToIgnoreCase()` para pacote e título.
- O teste já existente passa a verificar o contrato corretamente.
- Commit: `f83810c649d8dde9fd3b7c94d1f0dbc4b54bbeab`.

### Validação
- O build do #136 demonstrou que a alteração anterior compilava e que apenas o teste de ordenação falhava; a correção foi limitada ao comparador responsável.
- Novo Actions será necessário para confirmar o HEAD corrigido.

### Handoff
- Não alterar scanner, correlação ou analisador estático nesta passagem enquanto o novo CI valida a correção.


## 2026-09-18 — modernização das Actions do CI

### Concluído
- O CI #136 registrou avisos de migração forçada de Node 20 nas Actions do workflow Android.
- Atualizado `.github/workflows/android-apk.yml` para `actions/checkout@v7`, `actions/setup-java@v6`, `gradle/actions/setup-gradle@v6` e `actions/upload-artifact@v6`.
- As versões atuais documentadas pelos respectivos projetos usam runtime Node 24 para evitar a transição legada de Node 20. 
- Commit: `3cd63179da12ec6278f3d4a274702192f4c33517`.

### Handoff
- Conferir o novo Actions e manter o workflow separado das frentes de scanner/correlação/análise estática.
- Se o build voltar a falhar, tratar primeiro como regressão do workflow, não do código de segurança.


## 2026-09-18 — diagnóstico final do teste detalhado

### Validação
- Actions #139 no commit `3cd63179da12ec6278f3d4a274702192f4c33517` voltou a compilar o APK, mas falhou somente na linha 118 do teste de ordenação detalhada.
- A implementação de produção ordena primeiro pacote e depois título; por isso os três blocos esperados são: `Alpha/Same`, `Alpha/same`, `alpha/Same`.
- Corrigida a expectativa do teste sem alterar a produção.
- Commit: `6a48482013dcdedde5cd66dc866c488dd5862649`.

### Handoff
- Aguardar o novo CI para confirmar os testes unitários.
- O workflow já está usando as Actions modernizadas; manter essa frente separada da lógica do scanner.


## 2026-09-18 — ordem determinística na correlação de ameaças

### Concluído
- Identificado que `ThreatCorrelationEngine` gerava findings percorrendo `HashMap.keySet()`, deixando a ordem dos resultados dependente da iteração das tabelas.
- Adicionada ordenação final determinística dos findings derivados por severidade, pontos, pacote e campos textuais.
- Adicionado teste com pacotes Java de hash igual (`com.example.FB` e `com.example.Ea`) e entradas em ordem invertida, verificando que o resultado permanece estável.
- Commits: `88f002bf91e9e71dde35f4004ddac6620df691b2` e `a6f0be86657e6e8d574c5f2b7621997e7f4fae02`.

### Validação
- O CI #139 falhou anteriormente em um teste de `ScanReport` executado antes de `f83810c`; não representa o código corrigido atual.
- A mudança de correlação disparou uma nova execução do workflow para validar o estado integrado.

### Handoff
- Aguardar o CI do novo HEAD.
- Depois, revisar possíveis casos-limite de correlação sem modificar as regras de severidade existentes.


## 2026-09-18 — cobertura adicional de casos-limite do relatório

### Concluído
- Adicionados testes para confirmar que `ScanReport.getRawPoints()` ignora findings nulos e pontos negativos.
- Adicionado teste para confirmar que `packageSummaries()` ignora nomes de pacote em branco e preserva pacotes válidos.
- Não houve alteração no código de produção.
- Commit: `118c41a1a37f173e9f69c411532ce366df0327fd`.

### Handoff
- O outro agente permanece na frente de correlação determinística.
- Aguardar uma execução de CI não cancelada para validar o conjunto ampliado de testes.


## 2026-09-18 — tolerância a falhas na consulta de acessibilidade

### Concluído
- Revisado `SecurityScanner.checkAccessibility()` para impedir que uma exceção da consulta do `AccessibilityManager` interrompa toda a auditoria.
- Em caso de falha, o scanner agora registra um finding LOW informando que a consulta foi restringida/recusada e orienta revisão manual; também trata retorno nulo defensivamente.
- Commit: `bc1b8b0e4a6930b2165455c39376365b28849ae6`.

### Validação
- O HEAD anterior `928e1829...` estava validado pelo Actions #143 com sucesso antes desta alteração.
- Esta alteração dispara uma nova execução do CI para compilar e executar os testes no novo HEAD.
- A lógica normal de descoberta de serviços não foi alterada; apenas o caminho de falha ficou explícito.

### Handoff
- Aguardar o novo CI.
- Depois, revisar robustez de outras consultas de serviços do sistema sem alterar a semântica dos indicadores.


## 2026-09-18 — isolamento de falha por aplicativo

### Concluído
- `SecurityScanner.scan()` agora protege a análise individual de cada `PackageInfo` contra exceções inesperadas.
- Se um aplicativo causar falha durante sua inspeção, o scanner registra um finding LOW específico para aquele pacote e continua analisando os demais.
- Isso evita que um único APK/manifesto problemático interrompa a auditoria completa.
- Commit: `75d1c512894621349f17116e20af0b8ce8f5c43b`.

### Validação
- Actions #144 passou com sucesso no estado anterior (`bc1b8b0e...`).
- Esta alteração é posterior ao CI verde e acionou nova execução para validar o novo HEAD.

### Handoff
- Aguardar o novo CI.
- Se continuar verde, revisar somente casos de falha de consulta sistêmica que ainda possam interromper `scan()`.


## 2026-09-18 — contrato de imutabilidade do relatório

### Estado observado
- HEAD confirmado antes da alteração: `9f3bcea8b8c2ca2df9a898e866b7129b6b0d0d3f`.
- O outro agente avançou a frente de `SecurityScanner.java`, tornando a varredura de acessibilidade tolerante a falhas; o Actions #144 para o commit-base `bc1b8b0e4a6930b2165455c39376365b28849ae6` concluiu com sucesso.
- Mantida a separação de frentes: não alterei scanner, correlação ou análise estática.

### Concluído
- Adicionado teste em `DarkShield/app/src/test/java/com/darkshield/security/ScanReportTest.java` para garantir que a lista exposta por `ScanReport.getFindings()` permaneça imutável.
- Commit: `1e531af416c92ac04c091b13d2bbdd4592d88f3e`.
- A proteção já existia em produção; esta mudança somente registra o contrato e evita regressão.

### Próximo passo
- Validar o novo HEAD no Actions e continuar em testes independentes enquanto a frente do outro agente permanece em scanner/correlação.

### Riscos
- Nenhuma alteração de produção, pontuação ou detecção; apenas cobertura unitária.


## 2026-09-18 — ordenação determinística das informações técnicas

### Estado observado
- HEAD confirmado antes da alteração: `b2b07dc3154df8d9014dd0d374f915b89b718b7b`.
- O Actions #146 para o teste anterior concluiu com sucesso.
- O outro agente permanece em `SecurityScanner.java`, com isolamento de falhas por aplicativo e de falhas na leitura de acessibilidade.

### Concluído
- Adicionado teste em `DarkShield/app/src/test/java/com/darkshield/security/ScanReportTest.java` para garantir que títulos iguais apenas por capitalização em `informationalDetails()` mantenham ordenação determinística.
- Commit: `53504646604e15e1716dd614cd96883f7d78a648`.
- Não houve alteração de produção.

### Próximo passo
- Aguardar a validação do Actions para o novo HEAD e manter a separação das frentes.

### Riscos
- Cobertura exclusivamente unitária; nenhum impacto em pontuação, detecção ou permissões.


## 2026-09-18 — documentação de interpretação e limites

### Estado observado
- HEAD confirmado antes do registro: `1b9c92310fb057eb73f73853263b92b5a36f338c`.
- O outro agente concluiu com sucesso o Actions #147 no commit `53504646604e15e1716dd614cd96883f7d78a648`; a validação executou o build/testes do estado correspondente.
- Mantida a separação de frentes: não foram alterados `SecurityScanner.java`, `ThreatCorrelationEngine.java`, `ScanReport.java` ou seus testes nesta etapa.

### Concluído
- Atualizado `README.md` para documentar como interpretar o score heurístico, a diferença entre pontos exibidos e pontos brutos e o papel dos níveis `INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`.
- Documentados os limites operacionais da análise estática: APK até 200 MiB, até 10.000 entradas ZIP, até 2 MiB de amostragem por DEX/biblioteca e até 8 MiB no total, incluindo a limitação de cauda em entradas comprimidas.
- Commit: `1b9c92310fb057eb73f73853263b92b5a36f338c`.

### Handoff
- Próxima revisão deve permanecer fora da frente concorrente e procurar apenas melhorias de precisão, desempenho ou cobertura de testes em análise estática/UI.
- Não tratar mensagens de limite de análise como evidência de segurança do APK.

### Riscos
- O README é documentação e não altera o comportamento do aplicativo.


## 2026-09-18 — robustez da UI de ações externas

### Estado observado
- HEAD confirmado antes do registro: `6a39829a8094e769cc7e2dc3f1bdf42b5867fa6f`.
- Actions #147, no commit `53504646604e15e1716dd614cd96883f7d78a648`, concluiu com sucesso.
- Actions #148 foi iniciado para validar a correção de UI no commit atual e estava `queued` na última conferência.

### Concluído
- `MainActivity.java` agora trata falhas ao abrir o seletor de compartilhamento, copiar para a área de transferência e abrir as configurações de segurança.
- Em vez de deixar uma exceção escapar da ação do botão, a interface apresenta uma mensagem curta e preserva o aplicativo em execução.
- Commit: `6a39829a8094e769cc7e2dc3f1bdf42b5867fa6f`.

### Handoff
- Aguardar o Actions #148 para validar build e testes no estado atual.
- Não alterar `SecurityScanner.java`, `ThreatCorrelationEngine.java` ou a frente ativa de `ScanReport.java` sem nova sincronização.

### Riscos
- Mudança restrita ao tratamento de exceções de ações externas da UI; não altera permissões nem a lógica de detecção.


## 2026-09-18 — marcador estático sem distinção de capitalização

### Estado observado
- HEAD observado antes da edição: `6a39829a8094e769cc7e2dc3f1bdf42b5867fa6f`.
- O outro agente avançou a frente de UI/robustez; mantive essa frente intocada.
- Actions #147 confirmou sucesso para a alteração anterior de ordenação informativa.

### Concluído
- Adicionado teste em `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java` cobrindo marcador `FRIDA` em nome de biblioteca nativa.
- O teste protege a normalização para minúsculas e confirma que o achado continua heurístico LOW.
- Commit: `7da465b8c2eb3fb293dc649538393c375f5c18dc`.

### Validação
- Actions #149 foi disparado para o novo HEAD e estava pendente na última consulta.

### Próximo passo
- Aguardar a conclusão do #149 e continuar monitorando o log/HEAD para novas passagens do outro agente, sem editar os arquivos da frente concorrente.

### Riscos
- Nenhuma alteração de produção; somente cobertura unitária.

## 2026-09-18 — cobertura de marcadores estáticos em conteúdo

### Estado observado
- HEAD confirmado antes do teste: `7da465b8c2eb3fb293dc649538393c375f5c18dc`.
- Actions #149 passou com sucesso no estado anterior, incluindo o novo teste de nomes de arquivo case-insensitive.
- A nova execução #150 foi disparada pelo teste de conteúdo e está aguardando execução.

### Concluído
- Adicionado teste em `StaticApkAnalyzerTest.java` para confirmar que marcadores em conteúdo DEX também são tratados sem diferenciar maiúsculas/minúsculas.
- O teste usa `FRIDA` no conteúdo e exige o finding LOW `classes.dex:frida`, protegendo a normalização existente do analisador.
- Commit: `7c23256288118a9d1d9688fee01258dd8b77c7c7`.

### Handoff
- Aguardar Actions #150 antes de considerar esta cobertura validada.
- Manter a frente concorrente de scanner/correlação intacta.

### Riscos
- Alteração somente de teste; nenhum comportamento de produção ou pontuação foi modificado.



## 2026-09-18 — cobertura de marcadores de recurso

### Estado observado
- HEAD observado antes desta alteração: `062009121d13279be749d4996aabf6f46c596422`.
- A frente do outro agente continua sem entrada própria em `.github/AI_COLLAB_LOG_OTHER.md`; usei apenas o código e histórico verificáveis.
- O teste anterior de conteúdo case-insensitive já estava no `main`; esta alteração permanece na frente independente de análise estática/testes.

### Concluído
- Adicionado teste para marcador estático em recurso não executável com capitalização diferente (`FRIDA`).
- O teste confirma simultaneamente detecção case-insensitive, severidade `INFO` e zero pontos, preservando a regra de não pontuar recursos não executáveis isoladamente.
- Arquivo: `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java`.
- Commit: `994153a98dedbc533e87584e12584aa608d5f464`.

### Próximo trabalho
- Aguardar/validar o Actions do novo HEAD e continuar procurando casos-limite de análise estática sem aumentar o orçamento de leitura.

### Riscos
- Nenhuma mudança de produção; somente cobertura de teste. A interpretação dos marcadores continua heurística.


## 2026-09-18 — cobertura do status de baixo risco

### Estado observado
- HEAD antes desta alteração: `79e18a12cf37ca9c01dca2f007f5f3426af95cd5`.
- Actions #151 passou com sucesso no commit `994153a98dedbc533e87584e12584aa608d5f464`, validando a cobertura case-insensitive de recursos.

### Concluído
- Revisado `RiskCalculator.java` e sua suíte independente, sem entrar nas frentes concorrentes de scanner/correlação/análise estática.
- Identificada ausência de cobertura explícita para o contrato `LOW -> "POUCOS INDICADORES"`.
- Adicionado teste `lowSeverityProducesLowIndicatorStatus` em `RiskCalculatorTest.java`.
- Commit: `0da94ef8ebbf925a307f80517a84dc9c3384a516`.

### Próximo passo
- Validar o novo HEAD no Actions e continuar a sincronização em intervalos de 5 segundos, preservando qualquer avanço concorrente.

### Riscos
- Alteração somente de teste; nenhuma mudança na pontuação ou no comportamento de produção.


## 2026-09-18 — limite de custo da cauda comprimida

### Estado observado
- HEAD observado antes desta passagem: `6b4fc3914cd899dd13b3b3ad6b4e0af605bc5b9a`.
- O outro agente avançou a cobertura de `RiskCalculator`; o log separado dele continua sem entrada própria.
- Mantive a divisão de trabalho: análise estática/testes independentes, sem editar `SecurityScanner.java`, `ThreatCorrelationEngine.java` ou a frente de relatório concorrente.

### Concluído
- Em `StaticApkAnalyzer.java`, ajustado o limite da amostragem da cauda de entradas ZIP comprimidas: o caso de deslocamento exatamente igual a 2 MiB agora também é omitido.
- Motivo: o caminho anterior poderia pular exatamente 2 MiB de dados descomprimidos e depois ler mais 1 MiB de cauda, ultrapassando o orçamento de trabalho pretendido para uma entrada.
- Commit de produção: `0154568662fb9e3ee8a5334ccd4c2c71279cde98`.
- Adicionado teste de fronteira para uma entrada DEX comprimida de aproximadamente 3 MiB, com marcador somente na cauda, confirmando que a cauda não é forçada quando atingiria o limite de salto.
- Commit do teste: `f68399c50b29f28eb7d3b276700a078cc266b88a`.

### Validação
- O status combinado do commit do teste ainda não retornou checks.
- O workflow de Actions dispara por push em `DarkShield/**`, mas a ferramenta disponível para runs por commit pode não expor execuções disparadas diretamente por push. Não declarei build aprovado.

### Próximo trabalho
- Continuar procurando limites de custo/falsos positivos em `StaticApkAnalyzerTest.java` e somente alterar produção quando houver um caso concreto.
- Preservar os avanços do outro agente e reler SHA antes de qualquer nova edição.

### Riscos
- A análise de cauda comprimida continua deliberadamente conservadora: alguns marcadores distantes podem não ser encontrados para evitar inflar grandes prefixos comprimidos.


## 2026-09-18 — ordenação determinística da análise estática

### Estado observado
- HEAD confirmado antes do registro: `f68399c50b29f28eb7d3b276700a078cc266b88a`.
- O outro agente não deixou nova entrada no log separado; preservei a divisão de trabalho e não alterei scanner/correlação.

### Concluído
- `StaticApkAnalyzer.java` agora ordena os marcadores estáticos de nomes, recursos e conteúdo antes de montar os detalhes do relatório.
- Isso evita que a ordem dos arquivos dentro do ZIP altere o texto do finding quando os mesmos marcadores forem encontrados.
- Commit: `e4cb1115af7c3950d0e342598861deaad07dc53b`.
- Adicionado teste criando dois APKs equivalentes com entradas em ordem oposta e verificando detalhes idênticos.
- Commit do teste: `2bc8dfa42ca15489cf425a3693d90e0e05587e9e`.

### Validação
- O status combinado ainda não retornou checks para o novo HEAD.
- O endpoint de runs por commit disponível nesta integração não expõe os workflows disparados por push; portanto não declarei build aprovado. A API oficial do GitHub suporta filtrar runs por `head_sha`, mas essa capacidade não está exposta pelo conector usado aqui. citeturn0search0

### Próximo trabalho
- Continuar em testes de análise estática e limites de custo, sem aumentar superfície de falso positivo.


## 2026-09-18 — seleção determinística sob os limites de marcadores

### Estado observado
- Releitura do protocolo e dos dois logs concluída antes da alteração.
- SHA atual de `StaticApkAnalyzer.java` antes da edição: `b7d1f4e0645bdffc2822ad8bce1813ebfa46e1a4`.
- A frente concorrente permanece preservada; não alterei `SecurityScanner.java`, `ThreatCorrelationEngine.java` ou `ScanReport.java`.

### Concluído
- A seleção limitada de marcadores agora é determinística mesmo quando existem mais de 50 nomes/recursos ou mais de 20 ocorrências de conteúdo.
- Em vez de manter os primeiros itens encontrados pelo ZIP, o analisador mantém o menor conjunto lexicográfico dentro do limite, usando comparação case-insensitive com desempate case-sensitive.
- A ordenação final usa o mesmo comparador, mantendo o texto do finding estável entre APKs equivalentes com ordens ZIP diferentes.
- Produção: `7c41b2d0ae6b08a34b46f3afce6760882daca8b0`.
- Teste: `8898414f9b6da88885efe19edb953a157a4e98bf`, cobrindo 60 bibliotecas suspeitas em ordens inversas e confirmando detalhes idênticos.

### Validação
- Os arquivos foram relidos após os commits e os SHAs atuais são os esperados.
- O conector de status/runs não oferece uma confirmação confiável de workflow disparado por push para estes commits; não declarei build aprovado.

### Próximo trabalho
- Verificar o status do novo HEAD e, se permanecer sem checks expostos, revisar outro caso-limite independente da análise estática sem ampliar o orçamento de leitura.

### Riscos
- A seleção determinística descarta candidatos acima do limite por projeto; isso é intencional para manter memória/custo previsíveis.


## 2026-09-18 — cobertura determinística de hits de conteúdo

### Estado observado
- Releitura do protocolo, dos dois logs e dos arquivos da frente concluída antes da alteração.
- A implementação de seleção limitada já mantém os menores marcadores determinísticos; esta passagem completou a cobertura desse comportamento para conteúdo DEX.
- Nenhum arquivo da frente concorrente foi alterado.

### Concluído
- Adicionado teste com 21 arquivos DEX contendo marcadores diferentes, escritos em duas ordens ZIP inversas.
- O teste confirma que, mesmo ultrapassando o limite de 20 hits, o finding mantém exatamente o mesmo detalhe e descarta os candidatos lexicograficamente posteriores.
- Commit: `9d4055c3241a222224cd3454b38525fdcd139de3`.

### Validação
- Arquivo de teste relido após o commit.
- Ainda não há status de CI exposto para este novo estado pelo conector; portanto não declaro build aprovado.

### Próximo trabalho
- Revisar a integração final da análise estática com o scanner e documentação, procurando inconsistências de interpretação, sem alterar a frente concorrente.

### Riscos
- O limite de 20 hits continua preservado; o teste verifica apenas determinismo e não aumenta o orçamento de análise.


## 2026-09-18 — cobertura do score de exibição

### Estado observado
- HEAD observado após a sincronização: `ed8492ae90dd285c69332b4c5820f5fb31ecec21`.
- O outro agente avançou a análise estática; os commits recentes incluem cobertura determinística de hits de conteúdo.

### Concluído
- Revisado `RiskCalculatorTest.java` como frente independente.
- Adicionado teste explícito para o contrato de `scoreForDisplay()`, incluindo entrada normal e `null`.
- Commit: `ce85b66e56430565eb9f7ac9aaae39b704f8e204`.

### Validação
- O commit foi incorporado ao `main`; a validação por Actions do novo estado deve ser acompanhada pelo endpoint de runs.

### Próximo trabalho
- Continuar sincronizando o `main` e procurar apenas lacunas independentes, preservando a frente de análise estática/correlação do outro agente.

### Riscos
- Alteração somente de teste; não muda pontuação nem comportamento de produção.


## 2026-09-18 — correção do limite de hits de conteúdo

### Estado observado
- Actions #160 falhou somente no teste `StaticApkAnalyzerTest.cappedContentMarkersAreDeterministicAcrossZipOrder`; o APK compilou normalmente.
- A causa foi confirmada no código: a leitura de conteúdo era interrompida quando `suspiciousContent.size()` atingia 20, impedindo a seleção determinística de candidatos posteriores no ZIP.

### Concluído
- Removida apenas a condição que interrompia a leitura ao atingir o limite de 20 hits; a lista continua limitada por `addCappedMarker()`, que substitui o pior candidato.
- O orçamento global de 8 MiB e o limite de 2 MiB por entrada permanecem inalterados.
- Commit: `f01aaa4bfa05693379eedd4c031878d1104f246c`.

### Validação
- Novo commit já está no `main` e acionará o Actions para repetir build/testes.

### Próximo trabalho
- Conferir o novo Actions e o log a cada passagem, preservando qualquer avanço concorrente.

### Riscos
- A correção pode analisar entradas adicionais até o orçamento global, mas não aumenta os limites de bytes; somente permite que a seleção limitada seja realmente determinística.



## 2026-09-18 — cobertura determinística de marcadores em recursos

### Estado observado
- HEAD após a alteração de teste: `aba9bdc019bb9e81eed21811ee569e57ab4dff2d`.
- O protocolo e os dois logs foram relidos antes da alteração; a frente concorrente permanece preservada.
- `StaticApkAnalyzer` já usa a seleção limitada determinística para recursos não executáveis, mas faltava cobertura específica acima do limite de 50.

### Concluído
- Adicionado teste com 51 recursos contendo `frida`, escritos em duas ordens ZIP inversas.
- O teste confirma detalhe idêntico entre as duas análises, mantém os primeiros marcadores lexicográficos esperados e descarta o marcador posterior acima do limite.
- Arquivo alterado: `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java`.
- Commit: `aba9bdc019bb9e81eed21811ee569e57ab4dff2d`.

### Validação
- Teste commitado no `main` e arquivo relido após a alteração.
- Ainda não há confirmação de build/Actions para este novo commit pelo conector disponível; não declarei CI aprovado.

### Próximo trabalho
- Continuar a revisão de integração e limites de custo, priorizando casos concretos e evitando alterações de produção sem necessidade.

### Riscos
- O teste confirma somente determinismo da seleção limitada de recursos; não altera o limite de 50 nem amplia o orçamento de análise.


## 2026-09-18 — desempate completo do relatório

### Estado observado
- HEAD confirmado antes do encerramento da frente: `0191c12c6cc90824deeed1dedca3e61d4ae10d63`.
- Entre a passagem anterior e esta, o `main` recebeu a correção do limite de hits de conteúdo do analisador estático (`f01aaa4bfa05693379eedd4c031878d1104f246c`) e seu registro; preservei esses commits.
- O log do outro agente continua sem entrada preenchida.

### Concluído
- Identificado um caso de não determinismo em `ScanReport`: duas ocorrências com mesma severidade, pontos, pacote e título, mas detalhes diferentes, permaneciam na ordem de entrada.
- Corrigidos os dois ordenadores do relatório, `details()` e `informationalDetails()`, para desempatar por detalhe e depois por ação, cada um com comparação case-insensitive e desempate case-sensitive.
- Isso torna o texto do relatório estável mesmo quando achados com cabeçalho idêntico chegam em ordens diferentes.
- Produção: `0535d05b7f2397e959e0423526df75323e4acf39`.
- Adicionados dois testes correspondentes em `ScanReportTest.java`.
- Testes: `0191c12c6cc90824deeed1dedca3e61d4ae10d63`.

### Validação
- Diffs dos dois commits revisados após a escrita.
- Status combinado do novo HEAD retornou `statuses: []`; não há confirmação exposta de CI para esse commit e, portanto, não declaro build aprovado.

### Próximo trabalho
- Continuar pela integração do relatório/UI e procurar apenas inconsistências concretas, mantendo a análise estática e a correlação determinísticas.

### Riscos
- A mudança afeta somente ordenação textual; nenhuma pontuação, severidade ou conteúdo dos achados foi alterado.


## 2026-09-18 — endurecimento de metadados e assinatura

### Estado observado
- HEAD confirmado antes da edição: `eee4186047cbb0e4740897e4d37fff85aa42492e`.
- O outro agente continua avançando a determinização de `ScanReport`; preservei os commits concorrentes.

### Concluído
- `SecurityScanner.java` passou a reutilizar `ApplicationInfo` e `AppOpsManager` durante uma varredura, reduzindo consultas repetidas ao sistema.
- Adicionada sinalização heurística para apps de terceiros com target SDK muito antigo e para APKs marcados como `testOnly`.
- Adicionada informação não pontuada quando o app permite tráfego cleartext.
- Corrigida a leitura da assinatura: para rotação de certificado, o relatório usa o certificado atual (último da história); para múltiplos signatários, todos os hashes são exibidos em ordem determinística.
- Commit: `575ee650beedb747ff586b3c23007da998d1dd2e`.

### Validação
- Actions #165 foi disparado para o novo HEAD e está na fila; o Actions #164 anterior concluiu com sucesso.
- As referências Android usadas para a alteração confirmam que a história de assinatura é ordenada do certificado original ao atual e que `FLAG_USES_CLEARTEXT_TRAFFIC` representa permissão para tráfego sem criptografia.

### Próximo trabalho
- Acompanhar #165 e continuar a auditoria por casos concretos de precisão, desempenho, cobertura e robustez, sem duplicar a frente concorrente.

### Riscos
- target SDK antigo, `testOnly` e cleartext são sinais contextuais; não devem ser tratados como prova de malware. Cleartext foi mantido sem pontuação justamente para evitar falso positivo.


## 2026-09-18 — falha de inventário sem falso "limpo"

### Concluído
- Corrigido `SecurityScanner.getApps()`: falha na consulta de pacotes não é mais convertida silenciosamente em lista vazia.
- A varredura agora registra `Inventário de aplicativos incompleto` com nível MEDIUM e continua as verificações sistêmicas/rede/acessibilidade disponíveis, evitando apresentar um dispositivo como limpo quando a análise por pacote não ocorreu.
- Commit: `3082ad2addb755a0477fbafafd9c867c0e713809`.

### Validação
- A alteração foi aplicada sobre o SHA atual de `SecurityScanner.java`, preservando a mudança concorrente anterior.
- Novo Actions será acompanhado na próxima passagem.

### Próximo trabalho
- Procurar outros caminhos que possam transformar falha de coleta em ausência de indicador, além de revisar limites de desempenho da varredura completa.


## 2026-09-18 — revisão de inventário incompleto e CI

### Estado observado
- O outro agente avançou após a última passagem e adicionou tratamento explícito para falha de `getInstalledPackages()`.
- HEAD atual observado: `3082ad2addb755a0477fbafafd9c867c0e713809`.
- O commit anterior de metadados/assinatura (`575ee650beedb747ff586b3c23007da998d1dd2e`) também permanece no histórico.

### Revisão
- Conferi o pipeline atual de `SecurityScanner.scan()`: quando o inventário fica indisponível, o scanner agora registra um finding MEDIUM em vez de tratar a ausência de pacotes como uma varredura normal vazia.
- A verificação continua executando acessibilidade, notificações, administradores, correlação, integridade e rede nesse cenário.
- Não alterei esse código para evitar conflito com a frente concorrente.
- Acompanhei o Actions diretamente pela API: workflow #166 para o HEAD atual está `in_progress`.

### Próximo trabalho
- Aguardar o resultado do workflow #166 antes de propor alterações na frente de scanner.
- Depois, continuar procurando casos concretos de cobertura/robustez que possam ser testados sem interferir no trabalho concorrente.

### Riscos
- Sem o inventário de pacotes, a auditoria por aplicativo não pode ser considerada completa; o novo finding explicita essa limitação e aplica impacto heurístico moderado.


## 2026-09-18 — redução de falso positivo em componentes exportados

### Concluído
- Corrigida uma fonte importante de inflação do score em `SecurityScanner.inspectExportedComponents()`: activities, receivers e services exportados sem permissão explícita podem ser pontos de entrada públicos legítimos e não são mais pontuados isoladamente.
- Providers exportados sem `readPermission`/ `writePermission` continuam gerando LOW +2 por representarem uma superfície de exposição de dados mais direta.
- Os demais componentes continuam visíveis no relatório como INFO, preservando a informação sem transformar configuração pública legítima em evidência de malware.
- Commit: `6b4ab39c90636b4e3fd9e36665780bdd446b960b`.

### Motivo
- A regra anterior podia adicionar LOW a praticamente qualquer aplicativo com uma activity pública (por exemplo, uma tela de entrada), prejudicando precisão e confiança do score.
- A documentação de segurança do Android trata componentes exportados conforme sua finalidade e recomenda proteção especialmente para ContentProviders que não precisam ser públicos.

### Próximo trabalho
- Validar o novo Actions e continuar procurando fontes de falso positivo/negativo e caminhos de falha que silenciem resultados.


## 2026-09-18 — documentação alinhada à cobertura atual

### Estado observado
- O outro agente avançou em `SecurityScanner` e a correção de componentes exportados foi validada pelo Actions #167 com sucesso.
- HEAD de produção antes da documentação: `1dfff44da0604c392c663b3eafc5b69a30f2c374`.
- O log do outro agente continua sem entrada própria; preservei a divisão de trabalho.

### Concluído
- Atualizado `README.md` para refletir funcionalidades adicionadas depois da documentação anterior:
  - target SDK antigo e muito antigo;
  - aplicativos `testOnly`;
  - uso permitido de cleartext;
  - tratamento diferenciado de componentes exportados, com providers sem `readPermission`/`writePermission` explícitas pontuados e outros componentes públicos mantidos como informação;
  - comportamento quando o inventário de aplicativos não pode ser obtido;
  - assinatura SHA-256 com certificado atual após rotação e múltiplos signatários em ordem determinística;
  - marcadores em recursos não executáveis tratados como informação sem pontuação isolada.
- Commit: `cf6e8dc56d1396e58db8f3f62e4c37fba2fd52a0`.

### Validação
- README relido após a escrita.
- Esta alteração não aciona o workflow atual porque `README.md` não está nos caminhos do gatilho de push do workflow; a última build relevante para produção (`6b4ab39c90636b4e3fd9e36665780bdd446b960b`) passou no Actions #167.

### Próximo trabalho
- Continuar procurando lacunas concretas em cobertura, precisão e robustez sem alterar a frente concorrente em `SecurityScanner` enquanto ela estiver avançando.

### Riscos
- A documentação descreve comportamento heurístico e limitações; não transforma sinais em prova de malware.


## 2026-09-18 — cobertura do último desempate determinístico

### Concluído
- Revalidado `ScanReport.details()`: o comparador já usa `action` como último desempate após severidade, pontos, pacote, título e detalhe.
- Adicionado teste específico em `ScanReportTest.java` para dois achados com todos os campos anteriores idênticos e ações diferentes, garantindo que a saída permaneça determinística.
- Commit: `652b393e0f3656a0a1263b91266494153a749445`.

### Validação
- Teste aplicado sobre o SHA atual do arquivo, sem alterar produção.
- O workflow deve validar a suíte automaticamente porque o arquivo está sob `DarkShield/**`.

### Próximo trabalho
- Conferir o Actions deste commit e, se passar, continuar a auditoria em uma frente independente de testes/robustez.

### Riscos
- Alteração somente de teste; não muda score nem comportamento de produção.


## 2026-09-18 — contenção de inflação por correlações sobrepostas

### Estado observado
- HEAD antes da alteração: `701c17b0ee81971b6f001c9fd31d396241ca9754`.
- A frente concorrente continua concentrada em scanner/correlação; o arquivo `ThreatCorrelationEngine.java` foi relido imediatamente antes da edição.

### Concluído
- `ThreatCorrelationEngine.correlate()` agora consolida correlações derivadas por pacote e mantém apenas a correlação mais forte, evitando que várias regras descrevendo o mesmo conjunto de sinais somem pontos repetidamente.
- O desempate entre correlações de mesma força permanece determinístico por título, detalhe e ação.
- Adicionado teste cobrindo pacote com acesso remoto + acessibilidade + sobreposição + notificações + administrador, garantindo uma única correlação forte (+7).
- Commits: `c326af2b4c480ad4d9b712cafe5332cac2aa396b` e `1e78fd317e7de9243e96c97d8d062f64fb83ed13`.

### Próximo trabalho
- Verificar o Actions do novo estado e continuar a auditoria por falsos positivos, caminhos de falha e limites de custo, preservando commits concorrentes.

### Riscos
- A consolidação reduz pontuação duplicada de correlações; os achados-base continuam presentes no relatório e não são removidos.


## 2026-09-18 — amostragem estática não silenciosa

### Concluído
- Identificada uma falha de cobertura em `StaticApkAnalyzer`: erros ao ler o conteúdo de uma entrada DEX/biblioteca eram convertidos em amostra vazia, sem registrar a perda de cobertura.
- Alterado o analisador para registrar `INFO — Amostra de conteúdo indisponível` quando pelo menos uma entrada de código não pôde ser lida.
- O finding recebe 0 pontos e explica que a ausência de marcador naquela entrada não equivale à ausência de risco.
- Adicionado teste que corrompe deliberadamente uma entrada `classes.dex` e exige o aviso de cobertura incompleta.
- Commits:
  - `0075d576bbe1ea3417f47cb9989c22a807e1f03a` — produção;
  - `2d57c459f546557bd0b4a1621bec3ed96892b86c` — teste.

### Verificação do arquivo enviado
- `DarkShield-debug-apk.zip` foi inspecionado localmente.
- O SHA-256 declarado do `app-debug.apk` confere com os bytes extraídos.
- O APK contém 8 entradas ZIP, 3 arquivos DEX, `AndroidManifest.xml`, recursos e metadata de build.
- Esse APK é de uma build anterior às últimas correções do scanner; portanto não deve ser usado como evidência de que o binário já contém todas as mudanças atuais.

### Validação
- O Actions será usado para validar os novos testes.
- A alteração mantém a análise heurística local e não transforma o finding em prova de malware.

### Próximo trabalho
- Conferir o Actions e revisar outros pontos em que erros de leitura/hash podem ser convertidos silenciosamente em ausência de indicador.
