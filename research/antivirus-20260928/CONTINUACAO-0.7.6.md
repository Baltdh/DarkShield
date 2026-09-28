# Continuação da engenharia estática — DarkShield 0.7.6-test

28/09/2026. O ambiente foi restaurado do backup 0.7.5 entregue, preservando código e histórico. A amostra histórica Norton foi baixada novamente e teve o mesmo SHA-256 `7787c59d5daebe6b08df6076867abf242e9414bb11716169489666eb72bd7dee`.

## Avanço real da investigação

A análise passou do inventário de imports/exports para rastreamento estático limitado a partir de 11 exports de três DLLs extraídas. O script próprio `trace-exports.py` percorre até 64 blocos, 2048 instruções e dois níveis de chamadas diretas por export. As chamadas indiretas não resolvidas e blocos pendentes são registrados. Não houve execução de DLLs ou instaladores.

- `SDSLoaderGetHandle`: foram localizadas referências a LoadLibraryW, GetProcAddress, FreeLibrary e HeapAlloc no percurso limitado. Isso reforça a interpretação de uma camada de carregamento dinâmico.
- `SDSLoaderReleaseHandle` e `SDSReleaseUnusedResources`: referências a FreeLibrary; no primeiro também HeapFree. São compatíveis com liberação de módulos/recursos.
- `AvPreScn.GetFactory`: referências a operações de caminho de módulo e liberação de biblioteca; `PostRebootProc` referencia TraceMessage.
- `ccScanw.GetFactory`: referências de alocação e inicialização; não foi identificada nesta janela uma regra que classifique malware.

Evidência reproduzível: `reports/Norton-export-traces.json`. Ausência de uma API nessa janela não significa ausência na DLL. Chamadas observadas estaticamente não provam execução real. Os limites foram atingidos em vários percursos. O estudo continua sendo Windows histórico, sem inferência de implementação equivalente no Android.

## Aplicação ao nosso código

Carregadores e componentes separados mostram por que a unidade analisada importa. A leitura do DarkShield revelou problemas próprios, corrigidos nesta rodada:

1. **APKs divididos:** a cópia dos achados descartava origem, tags e atributos. Agora preserva todos esses campos e acrescenta a identificação da parte analisada. Um indício heurístico continua heurístico depois da agregação.
2. **Código sem extensão típica:** a seleção de splits considerava só nomes de arquivo, embora o analisador da base já reconhecesse assinaturas DEX/ELF. A seleção agora consulta os mesmos bytes iniciais, dentro do limite existente de entradas. Um `assets/payload.dat` com assinatura DEX também é analisado. Não se trata de execução ou desempacotamento recursivo.
3. **Cache e identidade:** mesmo caminho/tamanho/data não garantem o mesmo conteúdo. O cache passa a exigir SHA-256, e resultados novos são descartados se a identidade final não corresponder à inicial. O hash tem limite de 200 MiB e suporta cancelamento. Não é validação criptográfica da assinatura do APK nem proteção absoluta contra troca concorrente adversarial de arquivos.
4. **Cobertura explícita:** relatório informa entradas executáveis identificadas, amostradas, parcialmente lidas e bytes amostrados. Limites/ausências de leitura geram ANALYSIS_LIMIT/ANALYSIS_GAP, sem pontos de ameaça. A ausência de marcadores em uma amostra não é certificado de arquivo limpo.

Os testes novos reproduzem perda de procedência, DEX dentro de .dat em split, troca de conteúdo mantendo tamanho/data, reutilização do cache quando o conteúdo não mudou e amostragem parcial.

## Custo e limites

Revalidar identidade exige leitura sequencial do APK mesmo em cache hit. Uma análise nova lê o hash antes e depois; a descompressão e a inspeção continuam limitadas. Isso troca parte da economia de I/O por resultados associados ao conteúdo correto; precisa de medição em aparelho físico. Não foi incorporado motor proprietário, base de assinaturas ou um modelo treinado de malware. A revisão opcional por IA continua explicativa.
