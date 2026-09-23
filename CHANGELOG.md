# Histórico de versões

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
