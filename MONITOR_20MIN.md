# DarkShield — Monitor de continuidade

Atualizado: 2026-09-18 — auditoria contínua / correção de regressões

## Estado atual confirmado

- Repositório: `Baltdh/DarkShield`
- Branch: `main`
- O workflow `35322024413` foi confirmado **SUCCESS** em todas as etapas do commit `49e9b35b8f42a150a1b13ae99ea4b352a7a4a528`:
  - validação do projeto;
  - build debug APK;
  - testes unitários;
  - Android lint;
  - verificação de existência/tamanho do APK;
  - upload do artefato.
- Esse run é um baseline anterior às alterações posteriores.

## Alterações de auditoria já registradas

1. `StaticApkAnalyzer.java`: cauda comprimida além do orçamento passou de amostra vazia silenciosa para `null`, ativando `Amostra de conteúdo indisponível` sem pontuação.
   - Commit: `4ab95baf29a76799bb8daf96b4f14c8534b071ad`.
2. `StaticApkAnalyzerTest.java`: teste de cauda comprimida muito distante exige explicitamente o aviso de cobertura limitada e zero pontos.
   - Commit: `3dbf116892b014df48f181557d42dd67f786e239`.
3. `.github/workflows/android-apk.yml`: CI passou a validar o APK com `apksigner verify --verbose`, mantendo SHA-256 e arquivo não vazio.
   - Commit: `0897663eb68b4165cad90338498e08110c6c18d1`.
4. O CI foi posteriormente endurecido para descoberta robusta do `apksigner`, alinhamento via `zipalign -c -v 4`, e outras regressões de score/análise registradas pelos agentes seguintes.
5. `StaticApkAnalyzerTest.java` recebeu testes adicionais de cobertura parcial/zero-risco; o commit mais recente observado antes desta verificação foi `f21c48da891b0afc45bf66f39eacaac956954a3c`.

## Verificação do workflow mais recente

- Run mais recente observado na branch `main`: `35322604522` (run 189), disparado pelo commit `f21c48da891b0afc45bf66f39eacaac956954a3c`.
- Estado no momento desta atualização: **IN_PROGRESS**.
- Job `build`: `105528276540`.
- Já confirmado nesse job:
  - setup/checkout: sucesso;
  - JDK 17: sucesso;
  - Gradle 8.11.1: sucesso;
  - validação do projeto: sucesso;
  - build debug APK: **em andamento**;
  - testes, lint, verificação do APK, SHA-256, `zipalign` e `apksigner`: ainda pendentes.
- Um run intermediário (`35322572104`, run 188) foi cancelado pela concorrência quando o commit seguinte chegou; isso não é tratado como falha de código.
- Portanto, **não declarar o APK atual como validado/verde ainda**.

## Verificação do workflow mais recente

- Run `35322604522` terminou com **FAILURE** no job `build`.
- O build debug passou.
- Os testes unitários falharam em 2 casos:
  - `ScanReportTest.rawPointsCanExceedDisplayScoreCap`: a implementação atual aplica teto de 15 pontos por pacote antes da normalização; a expectativa antiga de 100 estava incompatível. O teste foi alinhado para esperar 45.
  - `StaticApkAnalyzerTest.partialCompressedSampleReportsCoverageAndKeepsHeadDetection`: a implementação retornava `null` para a amostra inteira quando somente a cauda comprimida estava indisponível, descartando uma detecção válida no cabeçalho.
- O log confirmou 91 testes e 2 falhas; lint e validação final do APK ficaram sem execução por causa da falha de testes.
- Correções aplicadas:
  1. `StaticApkAnalyzer.readContentSample()` preserva a amostra do cabeçalho quando a cauda não pode ser lida, mantendo o indicador de cobertura incompleta sem adicionar pontos.
     - Commit: `1d53b1a0b6a466e77cd8acd4811e1dc376aac42b`.
  2. `ScanReportTest` foi alinhado ao teto por pacote já implementado no `RiskCalculator`.
     - Commit: `4b3f639151e7c92f5e311fc6d0bf0a324d01403e`.
- O teto de score por pacote não foi revertido: ele é uma proteção deliberada contra inflação por múltiplos indicadores do mesmo pacote.
- Correção adicional após revisar a segunda falha: `StaticApkAnalyzer` agora marca explicitamente como cobertura parcial uma amostra menor que o orçamento esperado, enquanto preserva os marcadores encontrados no cabeçalho.
  - Commit: `4d4c9056a8e31b486fa069ac3f2ff710c95fd83d`.
- O próximo CI deve validar novamente build, testes, lint, APK, SHA-256, `zipalign` e `apksigner`.

## Artefato baseline verificado

- Artefato `DarkShield-debug-apk` do run `35322024413`: 44.400 bytes no ZIP do artefato.
- Digest do ZIP do artefato: `sha256:ec3ab8e48fcdd4a9910bf39754aaf4a4ee8b200446c657f8723992cbb500d947`.
- APK dentro do artefato: 48.285 bytes.
- SHA-256 do APK: `8616611ad08b9e4d650f852da14fc365f550372ce2b2da8075c2b51286a013d5`.
- O `.sha256` publicado continha o mesmo digest.
- `unzip -t` confirmou a integridade do pacote de artefatos.
- Esse artefato pertence ao commit `49e9b35b8f42a150a1b13ae99ea4b352a7a4a528`; não substitui a validação do run `35322604522`.

## Critérios de conclusão

Só considerar a cadeia atual concluída quando o run mais recente terminar com sucesso e houver confirmação concreta de build, testes unitários, lint, APK não vazio, SHA-256, alinhamento (`zipalign`) e `apksigner verify`.

## Próximas prioridades

- Reconsultar o run `35322604522` até terminar; se falhar, inspecionar o log concreto e corrigir somente o erro justificado.
- Depois da validação do CI, continuar a revisão da correlação de acesso remoto e das capacidades sensíveis.
- Continuar testes adversariais do ZIP/DEX/native com limites previsíveis de CPU/memória e resultados determinísticos.
- Preservar a distinção entre indicador heurístico, risco contextual e confirmação de malware.
- Limitações de cobertura devem ser explícitas e nunca virar pontos de risco automaticamente.

## Monitoramento

A automação disponível não executa um loop síncrono real de 20 em 20 segundos por 20 minutos; as verificações são feitas em etapas e o próximo ciclo agendado continua a cadeia. Nunca declarar sucesso apenas por compilação.
