# Estudo estático inicial de antivírus

28/09/2026. Quatro programas baixados de servidores dos fabricantes. Nenhum instalador ou DLL do antivírus foi executado. Foram usados parsers PE, desassemblagem limitada do ponto de entrada, leitura de recursos e extração de contêineres. Não houve instrumentação em execução, recuperação integral de código-fonte ou acesso aos serviços internos dos fabricantes.

## Amostras efetivamente examinadas

| Produto | Arquivo / versão declarada | Bytes | Escopo |
|---|---|---:|---|
| Avast | icarus_sfx / 26.9.11503.0 | 1.751.384 | Instalador Windows da página oficial; não é o motor completo |
| AVG | microstub / 2.1.137.0 | 256.440 | Pequeno iniciador de instalação Windows |
| Malwarebytes | MBSetup / 5.6.3.160 | 2.886.560 | Instalador Windows, com referências a serviço de instalação |
| Norton | NGC_Generic_SuperMUI / 22.24.8.36 | 245.422.936 | Pacote histórico Windows de 2024, hospedado no domínio do fabricante |

O link atual do suporte Norton `www.norton.com/latestn360` retornou 404 após redirecionar para `us.norton.com/latestn360`. O pacote histórico foi localizado pela comunidade Norton e obtido diretamente de `buy-download.norton.com`. Não representa a implementação atual do Norton nem a versão Android.

Hashes completos, URLs de origem e destino e horário de obtenção estão em `reports/*-provenance.json`. Versões são metadados declarados pelos arquivos. Os certificados PKCS#7 foram lidos; a assinatura Authenticode, cadeia de confiança e revogação **não foram validadas**. Isso difere da assinatura do nosso APK, que foi verificada por apksigner.

## Resultados e interpretação

### Avast
PE x86 de instalação, identificado como Icarus. Um recurso LZMA de 17.523 bytes foi descomprimido integralmente em 76.815 bytes com prefixo XML. A estrutura de recursos, metadados de instalador e imports de manipulação de arquivos/processos são compatíveis com inicialização e configuração da instalação. Não demonstram regras de malware. Certificados incluem o nome Gen Digital Inc.

### AVG
PE x86 com nome interno microstub e referência de compilação ao projeto microstub. Certificados incluem Gen Digital Inc. Há imports de criptografia, arquivos e criação de processos. O compartilhamento do fabricante/signatário com Avast e marcadores de empacotamento não prova que os dois usem as mesmas assinaturas ou decisões de classificação.

### Malwarebytes
PE x86 que importa WinVerifyTrust e funções de consulta a objetos criptográficos. Strings de instalação indicam seleção/obtenção de serviço instalador. Isso sustenta a hipótese de arquitetura de instalação em etapas; não prova que a validação de confiança seja aplicada corretamente em todos os caminhos. A lógica de classificação de malware não foi identificada nesse bootstrapper.

### Norton histórico: investigação dos contêineres
Foram reconhecidos **sete contêineres 7z**, nos offsets 1621514, 6487148, 236848159, 239502035, 240799623, 241162981 e 242441720. Seus inventários têm respectivamente 56, 2984, 15, 2, 41, 35 e 218 entradas. Contagens não equivalem a componentes exclusivos; incluem idiomas e arquivos de configuração.

O inventário mostra agrupamentos de definições, interface e componentes de varredura. Nomes de diretório não permitem concluir que todos os arquivos de definições sejam completos ou atuais. `InstallPackage/Engine.dll` pertence ao contexto do instalador: o nome “Engine” por si só não identifica o motor antimalware.

Do contêiner de `VirusScanner` foram analisados estaticamente:
- `ccScanw.dll`: interface exportada de criação de objetos (`GetFactory`, `GetObjectCount`), compatível com um componente modular.
- `sds_loader_x86.dll`: exports de inicialização, obtenção/liberação de handle e liberação de recursos (`SDSInitialize`, `SDSLoaderGetHandle`, `SDSLoaderReleaseHandle`, `SDSReleaseUnusedResources`). Sustentam a interpretação de uma camada carregadora, sem revelar a decisão de detecção.
- `AvPreScn.dll`: fábrica de objetos, saída de diagnóstico e rotina pós-reinicialização exportadas. O papel exato de cada função requer rastrear suas referências e fluxo de execução em uma próxima etapa.

A extração por py7zr encontrou filtro BCJ2 não suportado. Foi concluída com o 7-Zip oficial 26.03 para Linux, sem carregar/executar as DLLs. Hashes, imports e exports dos três módulos estão em `reports/Norton-scanner-modules.json`.

Nos quatro EXEs, foram desassembladas as primeiras 32 instruções a partir do entry point. Os relatórios preservam mnemônicos e transferências de controle, sem reproduzir código-fonte proprietário. Essa janela frequentemente contém inicialização do runtime; não é um grafo completo nem uma função de detecção identificada.

## Consequências para o DarkShield
Este estudo confirma a necessidade de distinguir instalador, carregador, scanner, dados e decisão. Não justifica copiar código proprietário nem atribuir precisão dos fabricantes ao DarkShield. As melhorias 0.7.5 vieram de problemas verificáveis no nosso código: confiança sem procedência, overflow e rótulos pouco explícitos; não de algoritmos secretos recuperados.

No Android, a próxima análise deve usar APKs oficiais e seus splits das versões escolhidas, com hash e certificado. Esses APKs não foram obtidos nesta rodada; o material binário examinado é Windows. Investigar manifestos/DEX/bibliotecas do Android é necessário antes de inferir equivalência. Não declaramos taxas de detecção ou equivalência com os fabricantes.

## Reprodução
Ambiente de análise: Python 3.12; versões em requirements.txt; 7-Zip Linux 26.03 obtido do link oficial em https://www.7-zip.org/download.html.

1. Criar diretórios `raw`, `reports`; instalar dependências de requirements.txt.
2. Executar `download.py` e `download-norton.py`. URLs móveis podem entregar versões diferentes; conferir hashes dos manifestos antes de comparar resultados.
3. Executar `analyze.py` e `inspect-containers.py`.
4. Definir SEVENZIP para o executável 7zz oficial e executar `inspect-norton-modules.py`.

Binários, DLLs extraídas e contêineres ficam fora do GitHub e do ZIP de análise. O repositório recebe scripts originais, metadados e conclusões. Não houve modificação de licenciamento, proteção do produto ou regras proprietárias.
