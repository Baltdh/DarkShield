# DarkShield — Comunicação entre agentes

Este arquivo é o ponto oficial de sincronização entre os GPTs que trabalham no repositório.

## Regra principal

Antes de modificar qualquer arquivo, leia este documento e confirme o estado atual de `main`. Nunca presuma que o HEAD, o SHA de um arquivo ou o conteúdo visto anteriormente ainda é o atual.

Depois de uma alteração:
1. Faça um commit pequeno e descritivo.
2. Registre a alteração e o próximo passo no log do seu agente.
3. Preserve todos os commits feitos pelo outro agente.
4. Se `main` avançou, releia o conteúdo atual e aplique sua mudança sobre o novo estado.
5. Não faça force-push e não reescreva histórico.

## Trabalho em paralelo

Cada agente deve preferir arquivos diferentes. Quando dois agentes precisarem do mesmo arquivo, consulte imediatamente o SHA atual desse arquivo antes de editar.

Os logs são separados para reduzir conflitos:
- `.github/AI_COLLAB_LOG_GPT56.md` — GPT-5.6 Luna
- `.github/AI_COLLAB_LOG_OTHER.md` — outro GPT/agente

Cada agente deve ler os dois logs antes de iniciar uma nova frente.

## O que registrar

Em cada entrada do log:
- data/hora;
- HEAD observado;
- o que foi concluído;
- arquivos alterados;
- testes/build relacionados;
- próximo trabalho;
- bloqueios ou riscos.

## Builds e trabalho contínuo

Uma build em andamento não impede trabalho em uma frente independente. Porém, não altere os mesmos arquivos que estão sendo validados sem primeiro verificar o HEAD atual.

Ao terminar uma frente:
1. confira novamente `main`;
2. confira o GitHub Actions;
3. registre o resultado;
4. deixe um próximo passo claro para o outro agente.

## Handoff

A mensagem mais recente de cada log deve ser tratada como o estado de passagem. Se o outro agente deixou uma tarefa “em andamento”, não assuma que está concluída só porque existe um commit relacionado; confira o código e o Actions.

## Estado conhecido na criação deste protocolo

O DarkShield está na versão 0.6.2. O projeto já possui auditoria local de permissões e acessos especiais, integridade do sistema, rede/proxy/VPN, análise estática limitada de APK, correlação entre sinais, resumo por pacote e relatório compartilhável.

O histórico recente também contém correções de deduplicação das correlações, navegação do resumo por pacote e ordenação determinística do relatório. O estado pode mudar rapidamente porque os dois agentes trabalham no mesmo `main`.

## Instrução para o outro GPT

Ao assumir o trabalho, leia este arquivo e `.github/AI_COLLAB_LOG_GPT56.md`. Crie/atualize `.github/AI_COLLAB_LOG_OTHER.md` com o seu estado e continue a partir do HEAD atual. Não reverta o trabalho do GPT-5.6 Luna.
