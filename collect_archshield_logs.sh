#!/bin/bash

# Script para coletar logs e diagnósticos do ArchShield
# Salva tudo em ~/Downloads/archshield_diagnostic.txt

OUTPUT_FILE="$HOME/Downloads/archshield_diagnostic.txt"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
echo "=== ArchShield Diagnostic Log - $TIMESTAMP ===" > "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Função para adicionar seção ao log
add_section() {
    echo "=== $1 ===" >> "$OUTPUT_FILE"
}

# 1. Confirmação do arquivo no_gui_archshield.py
add_section "Verificação do arquivo /tmp/no_gui_archshield.py"
ls -l /tmp/no_gui_archshield.py >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"

# 2. Teste do no_gui_archshield.py
add_section "Teste do no_gui_archshield.py"
sudo pkill -f "python3 /tmp/no_gui_archshield.py" 2>/dev/null
sudo python3 /tmp/no_gui_archshield.py > /var/log/archshield/archshield_debug_$(date +%Y-%m-%d).log 2>&1 &
sleep 2
cat /var/log/archshield/archshield_debug_$(date +%Y-%m-%d).log | head -n 100 >> "$OUTPUT_FILE" 2>&1
echo "(Apenas as primeiras 100 linhas do debug_no_gui.log foram incluídas)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# 3. Conteúdo do /var/log/archshield.log
add_section "Conteúdo do /var/log/archshield.log"
cat /var/log/archshield.log >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"

# 4. Verificação da porta 8080
add_section "Verificação da porta 8080"
sudo ss -tuln | grep 8080 >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"

# 5. Teste do curl para o dashboard
add_section "Teste do curl http://localhost:8080"
curl http://localhost:8080 >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
add_section "Teste do curl http://127.0.0.1:8080"
curl http://127.0.0.1:8080 >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
add_section "Teste do curl http://192.168.15.8:8080"
curl http://192.168.15.8:8080 >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"

# 6. Teste do test_flask.py
add_section "Teste do test_flask.py"
sudo pkill -f "python3 /tmp/test_flask.py" 2>/dev/null
sudo python3 /tmp/test_flask.py > /tmp/flask_test.log 2>&1 &
sleep 2
cat /tmp/flask_test.log >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
add_section "curl http://localhost:8080 (test_flask)"
curl http://localhost:8080 >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"

# 7. Ambiente
add_section "Versão do Python"
python3 --version >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
add_section "Caminho do Python"
which python3 >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
add_section "Tipo de Sessão (Wayland)"
echo $XDG_SESSION_TYPE >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
add_section "Processos do Hyprland"
ps aux | grep hyprland >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
add_section "Processos do Xwayland"
ps aux | grep Xwayland >> "$OUTPUT_FILE" 2>&1
echo "" >> "$OUTPUT_FILE"
add_section "Status do SELinux"
if command -v sestatus >/dev/null 2>&1; then
    sestatus >> "$OUTPUT_FILE" 2>&1
else
    echo "SELinux não instalado" >> "$OUTPUT_FILE"
fi


