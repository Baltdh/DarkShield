# Histórico de versões

## 0.7.2

- estrutura os achados com tags e proveniência de evidência (`OBSERVED`, `DECLARED`, `HEURISTIC`, `DERIVED`, `ANALYSIS_LIMIT`) para reduzir dependência de títulos/textos na correlação;
- atualiza o `RiskEngineV2` para separar evidências independentes, fortes e derivadas ao calcular confiança;
- adiciona atualização manual da base OSV pela URL oficial fornecida pelo AndroidX Security State, aceitando apenas HTTPS, com limites de tamanho/timeout e validação antes de substituir o cache;
- protege o cache OSV com gravação atômica, SHA-256 para detecção de corrupção e expiração lógica de sete dias;
- adiciona uma linha de base privada de privilégios observados e sinaliza novos acessos desde a última verificação como mudança a revisar, sem tratá-los automaticamente como malware;
- adiciona histórico local resumido das últimas 20 verificações, com limpeza manual e sem armazenar o relatório técnico completo;
- adiciona `EvidenceGraph` e `RiskEngineV2` como camada paralela para correlacionar evidências por pacote, separar risco de confiança e reduzir dependência de soma simples de permissões;
- exibe no relatório uma seção experimental de correlação por evidências sem substituir o score heurístico legado;
- integra `androidx.security:security-state:1.1.0` para leitura local separada do estado de patch do Android System, módulos Mainline e kernel, sem afirmar conformidade com CVEs sem relatório OSV;
- eleva o ambiente de compilação para `compileSdk 36` e AGP 8.10.1, mantendo `targetSdk 35` até concluir a auditoria de mudanças de comportamento do Android 16;
- integra a Central de correções e remoção confirmada pelo Android com o hardening e a cadeia de build reproduzível da linha 0.7.1;
- identifica MediaProjection e outros serviços privilegiados declarados sem tratá-los como ativos ou pontuar captura apenas declarada;
- diferencia administrador do dispositivo declarado de administrador realmente ativo;
- correlaciona captura de tela declarada com acesso remoto ou acessibilidade ativa, preservando a exigência de consentimento por sessão;
- adiciona análise heurística limitada de carregadores DEX combinados com rede, execução de comandos e pontes JavaScript de WebView;
- documenta a cobertura por tática da matriz MITRE ATT&CK Mobile e os limites de um scanner Android sem root;
- adiciona regressões para impedir que declarações isoladas sejam elevadas a comportamento operacional;
- informa DNS privado na rede ativa e oferece acesso aos ajustes de rede, sem pontuação de risco isolada;
- exige concessão da permissão antes de considerar AppOps como acesso operacional para permissões comuns;
- impede correlação de risco baseada apenas na declaração de sobreposição.

## 0.7.1

- reduz falso positivo ao não elevar um marcador nominal de acesso remoto por serviço de acessibilidade apenas declarado;
- mantém a elevação por capacidades operacionais e correlaciona acesso remoto com `WRITE_SETTINGS` ou `MANAGE_EXTERNAL_STORAGE` realmente ativos;
- adiciona testes de regressão para acessos especiais ativos e declarados;
- inclui Gradle Wrapper 8.11.1 com checksum oficial da distribuição;
- fixa GitHub Actions por SHA, valida o Wrapper e limita tempo de execução dos jobs;
- restringe a automação legada por issue ao proprietário do repositório e adiciona atualizações semanais via Dependabot;
- impede backup em nuvem e transferência dos dados privados do aplicativo por regras explícitas do Android 12+;
- remove verificações de versão inalcançáveis pelo `minSdk 26`, reduzindo ruído do Android lint.

## 0.7.0

- introduz base local de conhecimento de ameaças e contexto MITRE ATT&CK Mobile;
- adiciona Central de correções seguras com navegação para telas oficiais do Android;
- melhora progresso, cancelamento, diagnóstico de duração e cobertura de testes;
- mantém o modelo conservador: indicadores e correlações não são apresentados como prova automática de malware.
