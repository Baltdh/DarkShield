# DarkShield — Monitor de continuidade

Atualizado: 2026-09-18 04:59 BRT

## Estado desta etapa

- Repositório: `Baltdh/DarkShield`
- Branch: `main`
- Último problema confirmado no CI antes desta etapa: `lintDebug` falhou por `QueryAllPackagesPermission` no AndroidManifest.
- `assembleDebug` e testes unitários já haviam passado no run anterior.
- Correção aplicada nesta etapa:
  - `DarkShield/app/src/main/AndroidManifest.xml`
  - adicionada declaração `xmlns:tools`;
  - mantida `QUERY_ALL_PACKAGES`, necessária para o inventário local do scanner;
  - adicionado `tools:ignore="QueryAllPackagesPermission"`;
  - comentário documentando a finalidade local e a diferença em relação às políticas da Play Store.
- Commit da correção: `49e9b35b8f42a150a1b13ae99ea4b352a7a4a528`
- Workflow disparado: run `35322024413`
- No momento do registro, o workflow estava `in_progress`.

## Próxima verificação

1. Confirmar o resultado do run `35322024413`.
2. Se passar: validar artefato APK e SHA-256.
3. Se falhar: usar o log do job para corrigir o próximo erro concreto, sem mascarar problemas com baseline.
4. Continuar auditando score/correlação, análise estática ZIP e falsos positivos.
5. Manter a distinção entre indicador, risco e confirmação de malware.

## Observação sobre monitoramento

A checagem automática de 20 segundos durante 20 minutos não é uma cadência suportada pelo agendador. Foi programada uma rechecagem de continuidade após 20 minutos; verificações imediatas também estão sendo feitas nesta sessão.

## Regra para o próximo agente

Não declarar que o APK está pronto somente porque o código compila. Exigir CI verde, lint verde, testes verdes e artefato APK não vazio antes de considerar a etapa concluída.
