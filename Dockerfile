FROM python:3.11-slim

# Installation des dépendances système pour les bases de données
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    libmysqlclient-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie des requirements
COPY requirements.txt .

# Installation des dépendances Python (avec compilation)
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY blackops/ ./blackops/
COPY scripts/ ./scripts/
COPY config.yaml .
COPY data/ ./data/

# Création des dossiers nécessaires
RUN mkdir -p logs data/output data/ips

# Script d'entrée pour générer une liste d'IPs de test
RUN echo "127.0.0.1\n172.18.0.1\n$(hostname -i | awk '{print $1}')\
          \ntest-mongodb\ntest-mysql\ntest-postgres\ntest-redis\ntest-elasticsearch" \
          > /app/data/ips/test_targets.lst

# Variable d'environnement
ENV PYTHONPATH=/app
ENV BLACKOPS_CONFIG=/app/config.yaml

ENTRYPOINT ["python3", "scripts/blackops-cli.py"]
CMD ["--help"]