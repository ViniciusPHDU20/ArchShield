#!/bin/bash

# Define a pasta central de logs
LOG_DIR="/var/log/archshield"
mkdir -p "$LOG_DIR"

# Data atual pra organizar por dia
DATE=$(date +%Y-%m-%d)

# Move e organiza os logs existentes
mv /var/log/rkhunter.log "$LOG_DIR/rkhunter_$DATE.log" 2>/dev/null
mv /tmp/debug_no_gui.log "$LOG_DIR/archshield_debug_$DATE.log" 2>/dev/null

# Ajusta o collect_archshield_logs.sh pra salvar tudo na pasta central
# Usar sed -i para substituir os caminhos hardcoded pelo caminho correto do script
sed -i "s|/home/viniciusphdu/Downloads/collect_archshield_logs.sh|$(dirname "$0")/collect_archshield_logs.sh|g" "$(dirname "$0")/collect_archshield_logs.sh"
sed -i "s|/home/viniciusphdu/Downloads/collect_archshield_logs.sh|$(dirname "$0")/collect_archshield_logs.sh|g" "$(dirname "$0")/collect_archshield_logs.sh"

# Garante permissões
chmod -R 640 "$LOG_DIR"
chown -R root:adm "$LOG_DIR"

# Reinicia o serviço pra aplicar (ajuste o nome do serviço se diferente)
systemctl restart archshield.service 2>/dev/null || echo "Serviço não encontrado, reinicie manualmente"

echo "Logs centralizados em $LOG_DIR. Verifique e ajuste o caminho do collect_archshield_logs.sh!"


