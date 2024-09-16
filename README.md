# Sniffer de Pacotes em Python

Este projeto é um sniffer de pacotes em Python, desenvolvido para capturar e analisar pacotes de rede em tempo real. O sniffer utiliza sockets para capturar frames Ethernet e pacotes IP, e fornece informações detalhadas sobre protocolos como TCP, UDP e ICMP.
## Funcionalidades

    Captura de pacotes Ethernet e análise de informações básicas como endereços MAC e tipo de protocolo.
    Decodificação de pacotes IP, incluindo versão IP, TTL e protocolo.
    Análise de protocolos de transporte como TCP e UDP, exibindo informações sobre portas, sequências e dados.

## Tecnologias

    Python 3.x
    Módulos socket e struct

## Instalação

Clone este repositório e execute o script sniffer.py com permissões administrativas para capturar pacotes de rede:

```bash
git clone https://github.com/seu_usuario/seu_repositorio.git
cd seu_repositorio
sudo python3 sniffer.py
```

## Uso

O script captura pacotes de rede e imprime informações sobre cada pacote no console. As informações incluem endereços MAC, endereços IP, tipos de protocolos e detalhes específicos de protocolos de transporte.
Observações

    Este sniffer deve ser executado com permissões elevadas para acessar pacotes de rede.
    Certifique-se de usar este script em uma rede para a qual você tem permissão para monitorar.

## Licença

Este projeto está licenciado sob a Licença MIT.
