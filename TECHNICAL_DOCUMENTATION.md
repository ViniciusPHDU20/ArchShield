# ArchShield - Especificação Técnica e Arquitetura de Sistema

**Versão:** 2.1.0 (Stable/Secured)  
**Autor:** ViniciusPHDU20  
**Arquitetura:** Python 3.11+ (Backend) / Bash (Deploy) / HTML5+TailwindCSS (Frontend)

---

## 1. Visão Geral da Arquitetura
O ArchShield opera como um Sistema de Prevenção de Intrusão (IPS) em user-space, utilizando sniffing passivo de pacotes para alimentar um modelo de Machine Learning não supervisionado (Isolation Forest). O sistema é desacoplado em três camadas de execução concorrente gerenciadas por `threading`:

1.  **Core Sniffer:** Captura e extração de features de pacotes (Scapy).
2.  **Engine Analítica:** Detecção de anomalias e heurística de bloqueio (Scikit-Learn).
3.  **Interface de Gestão:** API REST e Dashboard via Flask.

---

## 2. Stack Tecnológica e Bibliotecas

### 2.1. Backend (Python 3)
A lógica principal reside em `/usr/bin/archshield` (compilado/instalado pelo script).

*   **Scapy (`scapy.all`):**
    *   *Função:* Manipulação de sockets raw e parsing de cabeçalhos IP/TCP/UDP.
    *   *Uso Crítico:* Método `start_sniffing` utiliza `sniff(store=False)` para evitar consumo excessivo de RAM durante capturas longas.
    *   *Fonte:* [PyPI/Scapy](https://pypi.org/project/scapy/)

*   **Scikit-Learn (`sklearn.ensemble.IsolationForest`):**
    *   *Função:* Detecção de anomalias baseada em densidade e isolamento de outliers.
    *   *Configuração:* `contamination=0.1` (10% de tolerância a ruído).
    *   *Vetor de Features:* `[comprimento_pacote, flag_tcp, flag_udp, ttl, porta_destino]`.
    *   *Fonte:* [PyPI/scikit-learn](https://pypi.org/project/scikit-learn/)

*   **Flask (`flask`):**
    *   *Função:* Microframework WSGI para servir a API de telemetria e o dashboard estático.
    *   *Segurança:* Executa em thread separada (`daemon=True`) para não bloquear o loop de captura.
    *   *Fonte:* [PyPI/Flask](https://pypi.org/project/Flask/)

*   **SQLite3 (`sqlite3`):**
    *   *Função:* Persistência local de cache de reputação de IPs e logs de eventos.
    *   *Implementação:* Utiliza `cursor.execute` com tuplas de parâmetros `(?,)` para mitigação total de SQL Injection.
    *   *Localização:* Biblioteca padrão do Python (`/usr/lib/python3.x/sqlite3`).

*   **Ipaddress (`ipaddress`):**
    *   *Função:* Validação estrita de strings de entrada para IPv4/IPv6.
    *   *Segurança:* Utilizado como gatekeeper antes de qualquer operação de `subprocess` ou `sqlite`.

### 2.2. Sistema e Rede
*   **Iptables:**
    *   *Função:* Firewall de nível de kernel (Netfilter) manipulado via user-space para DROP imediato de pacotes.
    *   *Chamada:* Via `subprocess.run(["iptables", ...])` evitando shell expansion.

---

## 3. Análise Detalhada dos Métodos e Fluxo de Dados

### 3.1. Inicialização e Configuração
O construtor `__init__` da classe `NetworkTrafficAnalyzer` orquestra o startup:
1.  **Carregamento de Configuração (`load_config`):** Lê `/etc/archshield.conf` via `configparser`. Se inexistente, gera defaults seguros.
2.  **Setup de Database (`setup_database`):** Inicializa o esquema SQL em `/var/log/archshield_ip_cache.db`.
    *   *Tabela:* `ip_info` (Cache de geoip e threat intelligence).
3.  **Threading:** Inicia o servidor Flask e o monitor de conexões (`ss -tunp`) em threads daemon.

### 3.2. Captura e Processamento de Pacotes
O ciclo de vida de um pacote é definido em `process_packet(packet)`:

1.  **Extração de Features (`extract_features`):**
    *   Converte o objeto binário do Scapy em um vetor numérico:
    *   `[len(pkt), is_tcp, is_udp, ttl, dport]`
    *   *Objetivo:* Normalizar dados para o modelo matemático.

2.  **Machine Learning (`IsolationForest`):**
    *   O modelo mantém um buffer deslizante (`packet_features`).
    *   A cada 100 pacotes (`len % 100 == 0`), o método `.fit()` recalibra a linha de base de "normalidade".
    *   `.score_samples()` calcula o grau de anomalia. Se `score < -0.5`, aciona o gatilho de bloqueio.

3.  **Thread Safety (`Lock`):**
    *   Utiliza `self.data_lock` (mutex) para garantir que a escrita nas listas de estatísticas (`traffic_data`) não colida com as leituras da API Flask.

### 3.3. Mecanismo de Defesa (Bloqueio)
O método `block_ip(ip, port)` implementa a resposta ativa:

1.  **Validação (`is_valid_ip`):** Verifica se a string é um endereço IP válido.
2.  **Whitelist Check:** Consulta `allowed_services` e portas permitidas para evitar auto-bloqueio (DoS acidental).
3.  **Execução de Firewall:**
    ```python
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    ```
    *Nota:* O uso de lista `[]` no subprocess anula riscos de Command Injection.
4.  **Agendamento de Desbloqueio:** Dispara uma thread temporizada (`unblock_ip_later`) que dorme por `block_duration` segundos antes de remover a regra.

### 3.4. API e Interface Web
O servidor Flask expõe endpoints JSON:

*   **`GET /status`:** Retorna snapshot das métricas em tempo real (pacotes/s, IPs bloqueados).
*   **`GET /ip_info/<ip>`:**
    *   Verifica cache local (SQLite) primeiro.
    *   Se *cache miss*, consulta API externa (`ip-api.com`).
    *   Valida entrada com `is_valid_ip` antes de qualquer processamento.
*   **`POST /block_ip` & `/unblock_ip`:**
    *   Recebe payload JSON.
    *   Valida sanitização do input.
    *   Executa ação no firewall.

---

## 4. Protocolos de Segurança Implementados

### 4.1. Mitigação de SQL Injection
Todas as queries SQL foram refatoradas para utilizar **Parameter Binding**.
*   *Inseguro (Anterior):* `f"SELECT ... WHERE ip = '{ip}'"`
*   *Seguro (Atual):* `execute("SELECT ... WHERE ip = ?", (ip,))`
O driver SQLite trata o input como literal, neutralizando metacaracteres SQL.

### 4.2. Mitigação de Command Injection
Nenhuma chamada de sistema utiliza `shell=True`. Todos os argumentos são passados como vetores de strings para `subprocess.run`.
*   A validação via `ipaddress.ip_address()` rejeita payloads que contenham operadores de shell (`;`, `|`, `&&`) antes mesmo da chamada ao sistema.

### 4.3. Prevenção de DoS no Banco de Dados
O acesso ao SQLite é feito sob demanda com conexões de curta duração (`open/execute/close`), evitando lock de arquivo prolongado em ambientes multithread.

---

## 5. Estrutura de Diretórios e Arquivos

*   `/usr/bin/archshield`: Executável principal (Python).
*   `/etc/archshield.conf`: Arquivo de configuração (Portas, Interfaces, Thresholds).
*   `/usr/share/archshield/templates/`: Arquivos HTML/JS do Dashboard.
*   `/var/log/archshield.log`: Log rotativo de operações e detecções.
*   `/var/log/archshield_ip_cache.db`: Banco de dados SQLite de reputação.

---
*Documentação gerada automaticamente com base na análise estática do código-fonte rev. 08f1070.*
