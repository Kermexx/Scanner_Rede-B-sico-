# Captura de Pacotes

# Este é um projeto Python para captura e análise de pacotes de rede usando a biblioteca Scapy. 
# Ele permite capturar pacotes de rede, exibir informações detalhadas sobre eles e gerar relatórios de captura.

## Pré-requisitos

# Certifique-se de ter instalado o Python 3.x e as seguintes bibliotecas:

# - Scapy
# - CustomTkinter

# Você pode instalar as dependências usando o pip:

import subprocess

subprocess.run(["pip", "install", "scapy"])
subprocess.run(["pip", "install", "customtkinter"])

## Funcionalidades

# - Captura de pacotes de rede.
# - Exibição de informações detalhadas sobre os pacotes capturados.
# - Possibilidade de filtrar a captura por tipo de protocolo (TCP, UDP).
# - Leitura e exibição de pacotes de arquivos PCAP.
# - Geração de relatórios de captura.

## Como Usar

# 1. Execute o script `captura_pacotes.py`.
# 2. Escolha a opção de captura de pacotes desejada:
#     - "Capturar todos os pacotes": Inicia a captura de todos os pacotes de rede.
#     - "Capturar apenas pacotes TCP": Inicia a captura de pacotes TCP.
#     - "Capturar apenas pacotes UDP": Inicia a captura de pacotes UDP.
#     - "Escolher arquivo PCAP": Abre um arquivo PCAP para visualização dos pacotes.
# 3. Os pacotes capturados ou lidos serão exibidos na interface, com detalhes sobre endereços IP, portas e informações específicas do protocolo.
# 4. Quando a captura terminar, um relatório será gerado.

## Observações

# - Certifique-se de ter permissões adequadas para capturar pacotes de rede.
# - Para a funcionalidade de captura de pacotes de rede, a duração padrão da captura é de 60 segundos.

# ---
# Este projeto foi desenvolvido por [seu_nome](https://github.com/seu_usuario). Se encontrar algum problema ou tiver sugestões, por favor, abra uma [issue](https://github.com/seu_usuario/nome_do_repositorio/issues).
