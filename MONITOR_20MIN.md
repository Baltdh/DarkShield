# DarkShield — Monitor de continuidade

Atualizado: 2026-09-18 — etapa de auditoria contínua

## Estado atual confirmado

- Repositório: `Baltdh/DarkShield`
- Branch: `main`
- O workflow `35322024413` foi confirmado **SUCCESS** em todas as etapas:
  - validação do projeto;
  - build debug APK;
  - testes unitários;
  - Android lint;
  - verificação de existência/tamanho do APK;
  - upload do artefato.
- Correção anterior de lint no `AndroidManifest.xml` permanece aplicada no commit `49e9b35b8f42a150a1b13ae99ea4b352a7a4a528`.

## Alterações desta continuação

1. `DarkShield/app/src/main/java/com/darkshield/security/analysis/StaticApkAnalyzer.java`
   - Antes: quando a cauda de uma entrada comprimida ficava além de `MAX_COMPRESSED_TAIL_SKIP_BYTES`, a função devolvia um array vazio e seguia como se o caminho de amostragem estivesse completo.
   - Agora: devolve `null`, ativando o aviso existente `Amostra de conteúdo indisponível`.
   - Motivo: evitar cobertura silenciosa e deixar explícito que a análise da entrada foi limitada.
   - Commit: `4ab95baf29a76799bb8daf96b4f14c8534b071ad`.

2. `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java`
   - O teste de cauda comprimida muito distante agora exige o aviso de amostra indisponível.
   - Mantém a regra de não transformar a limitação deliberada em pontos de risco.
   - Commit: `3dbf116892b014df48f181557d42dd67f786e239`.

3. `.github/workflows/android-apk.yml`
   - A etapa de verificação do APK agora procura o `apksigner` no Android SDK e executa `apksigner verify --verbose`.
   - O SHA-256 e o teste de arquivo não vazio continuam obrigatórios.
   - Commit: `0897663eb68b4165cad90338498e08110c6c18d1`.

4. `README.md`
   - Documentada a verificação de assinatura do APK no CI.
   - Comandos locais foram alinhados ao Gradle Wrapper (`./gradlew`) e incluem `lintDebug`.
   - Commit: `2d07c43415f6e391f780f0bf41e33a45cf868a0b`.

5. `.github/workflows/android-apk.yml`
   - A descoberta do `apksigner` foi tornada robusta para `ANDROID_HOME` ou `ANDROID_SDK_ROOT`.
   - Commit: `6eccb579543a9059994c3a119169b761e687d699`.

6. `DarkShield/app/src/test/java/com/darkshield/security/RiskCalculatorTest.java`
   - A cobertura antiga foi restaurada (null/empty, normalização, overflow, negativos/nulls, severidade, nível nulo, delegação para display).
   - As expectativas de normalização foram adaptadas ao novo teto de 15 pontos por pacote.
   - Mantidos os novos testes de contenção por pacote e de independência entre pacotes, além de um teste explícito para achados globais sem pacote.
   - Commit: `0fa4722d6cd856e394b17dd6e0caded003745f5a`.

## Trabalho paralelo observado

- `35f66f16c678bb46cae58ce71012fa6940608344`: contenção da pontuação heurística por pacote.
- `0fb745da1a2441d82fb88e960a6462e11ca897ed`: testes de regressão do score.
- O `RiskCalculator` atual usa teto de `15` pontos por pacote antes do multiplicador de exibição; o teste correspondente confirma que 10 achados de 4 pontos no mesmo pacote resultam em score 45, enquanto dois pacotes independentes de 10 pontos permanecem em 60.

7. `DarkShield/app/src/test/java/com/darkshield/security/analysis/StaticApkAnalyzerTest.java`
   - Adicionado teste de amostra comprimida parcial: marcador no trecho lido continua detectável e a cauda omitida gera aviso de cobertura sem pontuação.
   - O teste de cauda muito distante também exige explicitamente `0` ponto no aviso de amostra indisponível.
   - Commit: `f21c48da891b0afc45bf66f39eacaac956954a3c`.

## Estado de CI após os últimos commits

O run `35322024413` é verde e serve como baseline verificado antes das alterações finais. Os commits posteriores alteraram código/testes/workflow e, portanto, devem ser considerados **pendentes de nova validação** até que um novo workflow seja confirmado com sucesso, incluindo a verificação por `apksigner`.

## Próximas prioridades para o próximo agente

- Confirmar o workflow mais recente da branch `main`; não declarar APK pronto sem build, testes, lint, arquivo não vazio, SHA-256 e `apksigner verify`.
- Revisar a correlação de acesso remoto e a definição de capacidades sensíveis para reduzir falsos positivos sem perder sinais de alto valor.
- Continuar testes adversariais da análise estática ZIP/DEX/native, mantendo limites de CPU/memória e resultados determinísticos.
- Preservar a distinção entre indicador heurístico, risco contextual e confirmação de malware.
- Não aumentar score apenas porque uma amostra deixou de ser lida; limitações de cobertura devem aparecer como informação explícita.

## Monitoramento de 20 minutos

A cadência de uma checagem a cada 20 segundos durante 20 minutos não é suportada como loop síncrono contínuo pela automação disponível. Há uma rechecagem programada para 20 minutos após esta etapa, enquanto as verificações imediatas e correções justificadas são feitas nesta sessão.

## Regra de continuidade

Nunca declarar sucesso com base apenas em compilação. Exigir CI verde completo e verificar os artefatos/resultados concretos.

## Verificação independente do artefato CI verde anterior

- O artefato DarkShield-debug-apk do run 35322024413 foi baixado e inspecionado localmente.
- Tamanho do arquivo APK: 48.285 bytes.
- SHA-256 calculado: 8616611ad08b9e4d650f852da14fc365f550372ce2b2da8075c2b51286a013d5.
- O arquivo .sha256 publicado no artefato contém exatamente o mesmo digest.
- `unzip -t` confirmou a integridade do pacote de artefatos.
- O APK contém AndroidManifest.xml, 3 entradas DEX e nenhum .so nativo no artefato desse run.
- A busca direta por marcadores heurísticos conhecidos não encontrou ocorrências no APK desse run.
- Esse artefato corresponde ao commit 49e9b35b8f42a150a1b13ae99ea4b352a7a4a528, antes das alterações desta continuação; ele valida a cadeia anterior, não substitui a validação do novo workflow.
