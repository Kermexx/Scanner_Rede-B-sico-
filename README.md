# Ferramenta de Captura e Análise de Pacotes de Rede

Esta aplicação é uma ferramenta de captura e análise de pacotes de rede, desenvolvida em Python com a biblioteca Scapy e uma interface gráfica construída com customtkinter. Ela permite aos usuários capturar pacotes em tempo real, filtrar por tipo de protocolo, analisar arquivos PCAP e exibir os detalhes dos pacotes em uma interface gráfica amigável.

## Funcionalidades

- Captura de pacotes em tempo real com a possibilidade de filtrar por protocolo (TCP ou UDP).
- Análise e exibição de detalhes de pacotes de rede capturados.
- Funcionalidade para carregar e analisar arquivos PCAP.
- Geração de relatórios detalhados sobre a captura de pacotes.
- Interface gráfica intuitiva para uma interação fácil e eficiente.

## Instalação

Para executar esta ferramenta, você precisa instalar as bibliotecas Scapy e customtkinter. Você pode instalar todas as dependências necessárias com o seguinte comando:

```bash
pip install scapy customtkinter
```

## Como Usar

1. Clone ou baixe este repositório para o seu sistema.
2. Execute o script em algum local como Pycharm
3. Utilize os botões na interface gráfica para iniciar a captura de pacotes, filtrar por TCP ou UDP, carregar arquivos PCAP e mais.
4. Os resultados serão exibidos na interface gráfica e podem ser salvos em um relatório para análise posterior.

## Estrutura do Código

- `ComercarCaptura`: Classe responsável pela captura e análise dos pacotes.
- `AppInterface`: Classe que cria e gerencia a interface gráfica.




