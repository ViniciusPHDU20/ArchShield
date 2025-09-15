#!/bin/bash

# Script de instalação do ArchShield no Arch Linux

set -e

# Verifica se é root
if [ "$EUID" -ne 0 ]; then
    echo "Execute como root: sudo $0"
    exit 1
fi

echo "Iniciando instalação do ArchShield..."

# Verifica se o no_gui_archshield.py existe
if [ ! -f "no_gui_archshield.py" ]; then
    echo "Erro: no_gui_archshield.py não encontrado no diretório atual."
    exit 1
fi

# Instala dependências
echo "Instalando dependências..."
pacman -S --noconfirm python python-scapy python-pandas python-matplotlib python-scikit-learn tk python-flask python-requests || {
    echo "Erro ao instalar dependências."
    exit 1
}

# Copia o script principal
echo "Copiando no_gui_archshield.py para /usr/bin/archshield..."
cp no_gui_archshield.py /usr/bin/archshield
chmod 755 /usr/bin/archshield

# Cria arquivo de configuração
echo "Criando /etc/archshield.conf..."
cat > /etc/archshield.conf << 'EOL'
[DEFAULT]
interface=eth0
log_file=/var/log/archshield.log
rkhunter_log=/var/log/rkhunter.log
block_duration=3600
anomaly_threshold=0.1
allowed_ports=80,443,22,53
alert_email=your_email@example.com
flask_port=8080
EOL
chmod 644 /etc/archshield.conf

# Cria diretório de logs
mkdir -p /var/log/archshield
touch /var/log/archshield.log
chmod 644 /var/log/archshield.log

# Cria diretório para allowed_services.txt
mkdir -p /etc/archshield
touch /etc/archshield/allowed_services.txt
chmod 644 /etc/archshield/allowed_services.txt

# Configura serviço systemd
echo "Configurando serviço systemd..."
cat > /etc/systemd/system/archshield.service << 'EOL'
[Unit]
Description=ArchShield Network Traffic Analyzer
After=network.target

[Service]
ExecStart=/usr/bin/archshield
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable archshield
systemctl start archshield || {
    echo "Erro ao iniciar o serviço archshield."
    exit 1
}

# Cria dashboard web
echo "Criando dashboard web..."
mkdir -p /usr/share/archshield/templates
cat > /usr/share/archshield/templates/index.html << 'EOL'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>ArchShield Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto p-4">
        <h1 class="text-2xl font-bold mb-4">ArchShield - Monitor de Tráfego</h1>
        <canvas id="trafficChart" width="800" height="400"></canvas>
        <h2 class="text-xl font-bold mt-4">IPs Bloqueados</h2>
        <pre id="blockedIPs" class="bg-white p-4 rounded shadow"></pre>
    </div>
    <script>
        async function updateChart() {
            const response = await fetch(\'/status\');
            const data = await response.json();
            const ctx = document.getElementById(\'trafficChart\').getContext(\'2d\');
            new Chart(ctx, {
                type: \'line\',
                data: {
                    labels: data.times,
                    datasets: [{
                        label: \'Pacotes\',
                        data: data.packets,
                        borderColor: \'#1e90ff\',
                        backgroundColor: \'rgba(30, 144, 255, 0.2)\',
                        fill: true
                    }]
                },
                options: {
                    scales: {
                        x: { title: { display: true, text: \'Tempo (s)\' } },
                        y: { title: { display: true, text: \'Pacotes\' } }
                    }
                }
            });
            document.getElementById(\'blockedIPs\').textContent = data.blocked_ips.join(\'\\n\') || \'Nenhum IP bloqueado.\';
        }
        setInterval(updateChart, 5000);
        updateChart();
    </script>
</body>
</html>
EOL

echo "Instalação concluída!"
echo "Acesse o dashboard em http://localhost:8080"
echo "Para rodar manualmente: sudo archshield"
echo "Para verificar o serviço: systemctl status archshield"


