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

## Trabalho paralelo observado

- `35f66f16c678bb46cae58ce71012fa6940608344`: contenção da pontuação heurística por pacote.
- `0fb745da1a2441d82fb88e960a6462e11ca897ed`: testes de regressão do score.
- O `RiskCalculator` atual usa teto de `15` pontos por pacote antes do multiplicador de exibição; o teste correspondente confirma que 10 achados de 4 pontos no mesmo pacote resultam em score 45, enquanto dois pacotes independentes de 10 pontos permanecem em 60.

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