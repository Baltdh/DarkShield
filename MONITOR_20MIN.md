# DarkShield — Monitor de continuidade

Atualizado: 2026-09-18 — auditoria contínua / regressão verificada

## Estado atual

- Repositório: `Baltdh/DarkShield`
- Branch: `main`
- Baseline confirmado: run `35322024413` no commit `49e9b35b8f42a150a1b13ae99ea4b352a7a4a528` terminou SUCCESS com build, testes, lint, verificação do APK e upload.
- Artefato baseline: APK 48.285 bytes; SHA-256 `8616611ad08b9e4d650f852da14fc365f550372ce2b2da8075c2b51286a013d5`; ZIP do artefato digest `ec3ab8e48fcdd4a9910bf39754aaf4a4ee8b200446c657f8723992cbb500d947`.

## Alterações técnicas confirmadas

1. `StaticApkAnalyzer.java` — cauda comprimida além de `MAX_COMPRESSED_TAIL_SKIP_BYTES` não é mais tratada silenciosamente como amostra completa; `readTail()` retorna `null` e ativa `Amostra de conteúdo indisponível` sem pontos.
   - Commit: `4ab95baf29a76799bb8daf96b4f14c8534b071ad`.
2. `StaticApkAnalyzerTest.java` — teste de cauda distante cobre explicitamente a limitação de amostragem e zero risco.
   - Commit: `3dbf116892b014df48f181557d42dd67f786e239`.
3. `.github/workflows/android-apk.yml` — validação de APK foi endurecida com SHA-256, `zipalign` e `apksigner verify --verbose`; descoberta do `apksigner` foi tornada compatível com `ANDROID_HOME`/`ANDROID_SDK_ROOT`.
   - Commits registrados: `0897663eb68b4165cad90338498e08110c6c18d1`, `6eccb579543a9059994c3a119169b761e687d699`, `9abf066a26f9598d44a527188a4b57a2cc5a2838`.
4. `RiskCalculator` mantém teto de 15 pontos por pacote antes da normalização, reduzindo inflação por múltiplos achados do mesmo pacote.
5. `StaticApkAnalyzer` atual está no blob `0c08d9183d6ff7fc0719b8ab6776c82058493141`; portanto, não registrar como concluída nenhuma alteração que alegue preservação parcial do cabeçalho via commits diferentes sem revalidar o blob atual.

## Último CI efetivamente verificado

- Run `35322604522` (run 189), commit `f21c48da891b0afc45bf66f39eacaac956954a3c`, terminou **FAILURE**.
- Build debug: SUCCESS.
- Testes: FAILURE, 91 testes, 2 falhas.
- Falhas observadas no log:
  - `ScanReportTest.rawPointsCanExceedDisplayScoreCap`: expectativa antiga incompatível com o teto de 15 pontos por pacote; a versão atual do teste no `main` já espera 45.
  - `StaticApkAnalyzerTest.partialCompressedSampleReportsCoverageAndKeepsHeadDetection`: a implementação usada nesse run retornou a amostra inteira como indisponível quando a cauda comprimida estava além do limite, portanto o cabeçalho não chegou a ser pontuado/detectado.
- Por causa das falhas, nesse run o lint, `zipalign`, `apksigner`, SHA-256 final e upload não foram executados.
- O run intermediário `35322572104` foi CANCELLED por `concurrency` quando o commit seguinte chegou; não é evidência de falha de código.

## Estado de validação atual

- O commit atual de `main` inclui o monitor atualizado, mas esse arquivo não está no `paths` que disparam o workflow; portanto, a atualização do monitor não cria por si só um novo CI.
- Não existe, neste registro, um novo run verde após `f21c48da...` que valide simultaneamente as correções de análise estática e a cadeia `zipalign` + `apksigner`.
- **Não declarar APK atual como validado/verde.**

## Próximo agente

1. Revalidar o `StaticApkAnalyzer` atual e decidir entre semântica de amostra atômica (cauda indisponível => nenhum marcador da amostra) ou amostra parcial (cabeçalho preservado + flag explícita de cobertura). Se escolher parcial, implementar com estado explícito/objeto de resultado, não estado global frágil.
2. Executar/confirmar o teste correspondente antes de considerar o CI verde.
3. Confirmar novo workflow com build, unit tests, lint, APK não vazio, SHA-256, `zipalign` e `apksigner verify`.
4. Continuar revisão de correlação de acesso remoto, permissões sensíveis e falsos positivos.
5. Nunca transformar uma limitação de cobertura em evidência de malware.

## Observação de monitoramento

A automação disponível não executa um loop síncrono real de 20 em 20 segundos durante 20 minutos. As verificações são feitas em etapas; este arquivo é o ponto de continuidade para o próximo agente.
