# Log — outro GPT/agente

Use este arquivo para registrar a passagem de trabalho para o GPT-5.6 Luna.

## Entrada mais recente

- Data/hora:
- HEAD observado:
- O que foi concluído:
- Arquivos alterados:
- Build/testes:
- Próximo trabalho:
- Bloqueios/riscos:

## 2026-09-28 — pesquisa estática autorizada
- Main confirmado: 9734a87bd02edc204173c25d6fb6b364c110f98b. Branch de pesquisa independente das mudanças locais no APK.
- Usuário autorizou GitHub como armazenamento de análises. Adicionados pesquisa documental, diagnóstico Google, scripts próprios e metadados de quatro instaladores Windows. Norton histórico 22.24.8.36, demais links oficiais atuais na data.
- Validação: hashes, parsing PE, entry points, sete contêineres Norton; extração BCJ2 via 7-Zip e imports/exports de três DLLs. Sem executar produtos e sem publicar binários/bancos/código proprietário.
- APK 0.7.5-test validado separadamente (256 testes, release assinado) e entregue em backup; não faz parte desta branch. Google depende de captura do aviso, não foi declarado resolvido.
- Próxima etapa: APKs Android oficiais e corpus de validação, teste físico da remoção. Resultados aqui não provam motores equivalentes entre Windows/Android.


## 2026-09-28 — continuação 0.7.6
- Base da pesquisa: c57074b830202bd8b72f46f6758d80298f8d57f6; main confirmado 9734a87bd02edc204173c25d6fb6b364c110f98b.
- Rastreamento estático limitado de 11 exports em três DLLs Norton históricas. SHA da amostra recuperada confirmado; sem executar o produto. Evidências e script anexados.
- Problemas próprios encontrados/aplicados ao APK local: procedência de splits, seleção por magic DEX/ELF, identidade SHA-256 no cache e cobertura estruturada. Validação do APK registrada no backup de teste separado.
- Próximo passo: APK Android oficial e testes físicos de custo de I/O e remoção. Pesquisa não identifica regras proprietárias de detecção. Branch contém só análises.
