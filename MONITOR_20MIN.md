# DarkShield — Monitor de continuidade

Atualizado: 2026-09-18 — auditoria contínua / correção de regressões

## Estado atual

- Repositório: `Baltdh/DarkShield`
- Branch: `main`
- Último CI concretamente verificado: run `35322604522`, que terminou em **FAILURE** no job `105528276540`.
- Nesse run, o build debug passou e os testes unitários falharam em 2 casos. O lint e as verificações finais do APK foram pulados por causa da falha dos testes.
- O baseline anterior `35322024413` foi confirmado **SUCCESS** em validação do projeto, build, testes, lint, existência/tamanho do APK e upload.

## Correções aplicadas após a falha do CI

1. `StaticApkAnalyzer.readContentSample()` passou a preservar uma amostra de cabeçalho legível quando somente a cauda comprimida está fora do orçamento, mantendo a detecção útil sem fingir cobertura completa.
   - Commit: `1d53b1a0b6a466e77cd8acd4811e1dc376aac42b`.

2. `ScanReportTest.rawPointsCanExceedDisplayScoreCap` foi alinhado ao contrato atual do `RiskCalculator`: pontos brutos podem exceder o teto de exibição por pacote, enquanto o score é limitado pelo teto de pontos por pacote.
   - Commit: `4b3f639151e7c92f5e311fc6d0bf0a324d01403e`.
   - O teto de `15` pontos por pacote foi mantido deliberadamente para reduzir inflação por múltiplos sinais no mesmo pacote.

3. O analisador passou a marcar explicitamente cobertura parcial quando uma entrada grande retorna menos bytes que o orçamento solicitado, preservando simultaneamente os marcadores encontrados no cabeçalho.
   - Commit: `4d4c9056a8e31b486fa069ac3f2ff710c95fd83d`.

4. Foi registrado no monitor que a correção de cobertura parcial está concluída.
   - Commit: `9bc2003eb366188e4bc00608b1745a0030870948`.

## Novas alterações desta etapa

5. `RiskCalculator`: `globalPoints` deixou de usar `int` e passou para `long`. Isso elimina uma rota de overflow quando há vários achados globais com pontuações muito grandes; a normalização para 0–100 continua sendo feita após a soma.
   - Commit: `5cd0a631d5b1424f2e360ec27c93091f8a71a274`.

6. `RiskCalculatorTest`: adicionada regressão com dois achados globais de `Integer.MAX_VALUE`, exigindo score final de 100 em vez de comportamento dependente de overflow.
   - Commit: `c8a5b30572ebd4a556a964d62183f877ea8c1c61`.

7. CI: o passo de build recebeu o id `build_apk`. Lint e validação do APK agora usam `always()` condicionados ao sucesso do build, portanto uma falha dos testes unitários não impede a coleta independente de lint, SHA-256, `zipalign` e `apksigner`.
   - Commit: `1d5b647f513d04a7dcc3d92521745374f41f6c3c`.
   - Upload continua condicionado ao fluxo normal para não publicar artefato de uma cadeia incompleta.

## Próxima verificação obrigatória

- O próximo run disparado pelos commits acima precisa ser confirmado no GitHub.
- Só considerar a cadeia atual verde quando o mesmo run confirmar, de forma concreta:
  - projeto válido;
  - build debug;
  - todos os testes unitários;
  - Android lint;
  - APK não vazio;
  - SHA-256;
  - `zipalign -c -v 4`;
  - `apksigner verify --verbose`.
- O conector GitHub disponível nesta sessão não expõe uma listagem geral dos runs de push; a consulta por commit atualmente retorna somente runs de pull request. Por isso, não registrar "SUCCESS" sem obter o run e seus passos diretamente.
- O último run conhecido continua sendo `35322604522` = **FAILURE** até que um run posterior seja comprovado.

## Continuidade da auditoria

Depois do CI verde, continuar em paralelo na análise de segurança, priorizando correlação de acesso remoto, capacidades sensíveis, falsos positivos e testes adversariais de ZIP/DEX/native. Limitações de cobertura devem ser visíveis e nunca virar pontuação automaticamente.

## Monitoramento de 20 minutos

A automação disponível não executa um loop síncrono real de 20 em 20 segundos por 20 minutos; esse intervalo foi tratado como ciclos de verificação separados. Nunca afirmar que 30 verificações de 20 segundos foram executadas sem evidência real.
