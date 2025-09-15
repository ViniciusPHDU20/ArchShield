# Projeto ArchShield

Este projeto é um monitor de tráfego de rede com detecção de anomalias e funcionalidade de bloqueio de IP, desenvolvido para Arch Linux.

## Estrutura do Projeto

- `no_gui_archshield.py`: O script principal em Python que realiza a análise de tráfego, detecção de anomalias e interage com o `iptables` para bloqueio de IPs. Ele também contém um servidor Flask para o dashboard web.
- `install_archshield.sh`: Script de instalação inicial do ArchShield, responsável por instalar as dependências necessárias via `pacman`, copiar o script principal para `/usr/bin/archshield`, configurar o arquivo de configuração `/etc/archshield.conf`, criar o serviço `systemd` e configurar o dashboard web.
- `centralize_archshield_logs.sh`: Script para centralizar os logs do ArchShield.
- `collect_archshield_logs.sh`: Script para coletar os logs do ArchShield.
- `PKGBUILD`: Arquivo para construção de pacotes no Arch Linux.
- `script.sh`: Este script automatiza a atualização do `index.html` e do `no_gui_archshield.py`, além de reiniciar o serviço do ArchShield. Ele também cria backups dos arquivos antes de modificá-los.

## Alterações Recentes (via `script.sh`)

O script `script.sh` foi fornecido pelo usuário para automatizar as seguintes modificações:

1.  **Atualização do `index.html`:**
    -   Adição de uma tabela para exibir IPs ativos em tempo real.
    -   Implementação de funcionalidade de clique direito para bloquear IPs diretamente do dashboard.
    -   Ajustes no gráfico de tráfego para melhor visualização.

2.  **Atualização do `no_gui_archshield.py`:**
    -   Adição de uma nova rota `/block_ip` no servidor Flask para permitir o bloqueio manual de IPs via dashboard.
    -   Implementação de uma thread para monitorar conexões ativas (`monitor_active_connections`).
    -   Ajustes na lógica de detecção de anomalias e processamento de pacotes.
    -   Correção de um erro de sintaxe anterior.

## Como Usar o `script.sh`

Para aplicar as atualizações no projeto, execute o `script.sh` com privilégios de root:

```bash
sudo ./script.sh
```

Este script fará backup dos arquivos existentes, aplicará as novas versões do `index.html` e `no_gui_archshield.py`, e reiniciará o serviço do ArchShield.

## Próximos Passos

Qualquer modificação futura no projeto deve ser encapsulada em um script similar ao `script.sh` para garantir a automação, rastreabilidade e facilidade de aplicação das alterações.

