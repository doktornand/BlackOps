================================================================================
                           BLACKOPS - DEEP SERVER ANOMALY SEARCHER
                           =======================================
                          Guide d'utilisation complet (v1.0)
================================================================================


╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                       ⚠️  AVERTISSEMENT LÉGAL & ÉTHIQUE  ⚠️                                           ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                                                       ║
║  BlackOps est un outil de DÉTECTION D'ANOMALIES et d'AUDIT DE SÉCURITÉ. Il est conçu POUR :                           ║
║                                                                                                                       ║
║     ✓  Analyser vos PROPRES serveurs et infrastructures                                                               ║
║     ✓  Réaliser des audits de sécurité avec autorisation ÉCRITE et PRÉALABLE                                          ║
║     ✓  Tester la configuration de vos bases de données en environnement contrôlé                                      ║
║     ✓  Former des équipes à la détection d'anomalies (CTF, labos)                                                     ║
║                                                                                                                       ║
║  L'utilisation de BlackOps sur des systèmes, réseaux ou serveurs dont vous n'êtes PAS LE PROPRIÉTAIRE ou sans         ║
║  AUTORISATION EXPLICITE est :                                                                                         ║
║                                                                                                                       ║
║     ✖  ILLÉGALE (conformément aux articles 323-1 à 323-7 du Code pénal - accès frauduleux à un système)               ║
║     ✖  CONTRAIRE À L'ÉTHIQUE PROFESSIONNELLE                                                                          ║
║     ✖  PASSIBLE DE POURSUITES PÉNALES (amende, peine d'emprisonnement)                                                ║
║                                                                                                                       ║
║  EN UTILISANT CET OUTIL, VOUS ACCEPTEZ :                                                                              ║
║      - De n'utiliser BlackOps que sur des cibles autorisées                                                           ║
║      - De conserver des PREUVES ÉCRITES d'autorisation (email, contrat, ordre de mission)                             ║
║      - D'assumer l'entière responsabilité légale de vos actions                                                       ║
║      - De ne pas partager les résultats sensibles sans accord explicite                                               ║
║                                                                                                                       ║
║  ⚠️  CE LOGICIEL EST FOURNI "EN L'ÉTAT", SANS GARANTIE D'AUCUNE SORTE. L'AUTEUR DÉCLINE TOUTE RESPONSABILITÉ          ║
║      EN CAS D'USAGE MALVEILLANT OU NON AUTORISÉ.                                                                      ║
║                                                                                                                       ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝


TABLE DES MATIÈRES
------------------
1.  Présentation
2.  Installation
3.  Configuration
4.  Utilisation de base
5.  Options avancées
6.  Modules disponibles
7.  Interprétation des résultats
8.  Docker / Conteneurisation
9.  Dépannage
10. Bonnes pratiques
11. Exemples concrets


================================================================================
1. PRÉSENTATION
================================================================================

BlackOps est un toolkit de détection d'anomalies profondes sur serveurs.
Il scanne les services suivants via proxy (SOCKS5/HTTP) et analyse :

  - MongoDB         (ports 27017, 28017)
  - MySQL           (port 3306)
  - PostgreSQL      (port 5432)
  - Redis           (port 6379)
  - Elasticsearch   (ports 9200, 9300)
  - Kubernetes API  (ports 6443, 8001)

Chaque module détecte :
  ✓ authentification faible ou absente
  ✓ versions obsolètes / vulnérables
  ✓ configurations dangereuses
  ✓ données sensibles exposées
  ✓ anomalies temporelles

Le résultat est un score d'anomalie (0.0 à 1.0) et un rapport multi-format.


================================================================================
2. INSTALLATION
================================================================================

2.1 Prérequis système

  - Python 3.9 ou supérieur
  - pip
  - optionnel : Docker / Docker Compose

2.2 Installation standard

  # Cloner / extraire les fichiers
  cd /opt/
  git clone https://github.com/V-Demon/BlackOps.git
  cd BlackOps

  # Créer l'environnement virtuel (recommandé)
  python3 -m venv venv
  source venv/bin/activate    # Sur Windows : venv\Scripts\activate

  # Installer les dépendances
  pip install -r requirements.txt

  # Rendre le script exécutable
  chmod +x scripts/blackops-cli.py

2.3 Installation Docker

  # Construire l'image
  docker-compose build

  # Ou construire manuellement
  docker build -t blackops:latest .


================================================================================
3. CONFIGURATION
================================================================================

3.1 Fichier principal : config.yaml

  Voici les paramètres essentiels à personnaliser :

  # PROXY (obligatoire pour l'anonymisation)
  proxy:
    socks5:
      host: 192.168.1.20    # Adresse de votre proxy SOCKS5
      port: 9050            # Port par défaut de Tor
      enabled: true

  # FURTIVITÉ
  stealth:
    jitter_min: 0.5         # Pause min entre scans (secondes)
    jitter_max: 2.5         # Pause max entre scans
    randomize_order: true   # Mélanger l'ordre des IPs

  # SEUILS D'ANOMALIE
  anomaly_detection:
    slow_threshold_ms: 200  # Requête >200ms = anomalie
    error_burst_threshold: 3

  # MODULES ACTIVÉS/DÉSACTIVÉS
  modules:
    mongodb:
      enabled: true
    mysql:
      enabled: true
    redis:
      enabled: true
    # ...

3.2 Variables d'environnement

  Exportez ces variables si nécessaire :

  export K8S_TOKEN="votre_token_ici"
  export K8S_CA_CERT="/path/to/ca.pem"
  export BLACKOPS_CONFIG="/custom/path/config.yaml"

3.3 Fichiers d'entrée (listes d'IPs)

  Les listes d'IPs sont des fichiers texte brut avec une IP par ligne :

  # Exemple : data/ips/targets.lst
  192.168.1.10
  192.168.1.20
  10.0.0.5
  172.16.0.100

  Les noms de fichiers sont libres. Par convention, utilisez :
    - _scrambled.lst    pour bops.py (scan multi-services)
    - _27017.lst        pour MongoDB
    - _3306.lst         pour MySQL
    - _5432.lst         pour PostgreSQL
    - _6379.lst         pour Redis
    - _9200.lst         pour Elasticsearch
    - _6443.lst         pour Kubernetes


================================================================================
4. UTILISATION DE BASE
================================================================================

4.1 Scanner toutes les cibles d'un fichier

  python3 scripts/blackops-cli.py \
    --ip-list data/ips/targets.lst \
    --output mon_scan

4.2 Scanner un module spécifique

  python3 scripts/blackops-cli.py \
    --ip-list data/ips/targets.lst \
    --module mongodb \
    --output scan_mongo

4.3 Mode deep (détection d'anomalies avancée)

  python3 scripts/blackops-cli.py \
    --ip-list data/ips/targets.lst \
    --output scan_profond \
    --deep

  Ce mode active :
    - analyse temporelle (baseline)
    - détection de patterns suspects
    - score d'anomalie plus précis

4.4 Désactiver le proxy (scan direct)

  python3 scripts/blackops-cli.py \
    --ip-list data/ips/targets.lst \
    --no-proxy \
    --output scan_direct


================================================================================
5. OPTIONS AVANCÉES
================================================================================

5.1 Options de la CLI

  Usage: blackops-cli.py [-h] [-c CONFIG] [-i IP_LIST] [-m MODULE] [-o OUTPUT]
                         [--no-proxy] [--deep] [--verbose] [--format FORMAT]

  Options :
    -h, --help            Affiche l'aide
    -c, --config          Fichier de configuration (défaut: config.yaml)
    -i, --ip-list         Fichier contenant les IPs cibles (obligatoire)
    -m, --module          Module spécifique (mongodb, mysql, postgresql, redis,
                          elasticsearch, kubernetes)
    -o, --output          Préfixe des fichiers de sortie (défaut: blackops_scan)
    --no-proxy            Désactive l'utilisation du proxy
    --deep                Active la détection d'anomalies approfondie
    --verbose             Affiche les logs détaillés dans la console
    --format {csv,json,html}
                          Format de sortie unique (défaut: tous)

5.2 Variables de runtime

  Pour ajuster les timeouts sans modifier config.yaml :

  export BLACKOPS_TIMEOUT=10
  export BLACKOPS_PARALLEL=3
  export BLACKOPS_RATE_LIMIT=0.5

5.3 Scripts individuels (hérités)

  Les scripts originaux sont toujours utilisables :

  # Scanner multi-services
  python3 bops.py

  # Scanner Elasticsearch
  python3 Discover.py

  # Scanner Kubernetes
  python3 api-search.py

  # Scanner MongoDB (low-level)
  python3 MongoSnopeR2b1.py

  # Scanner MySQL
  python3 MysqlSnopeR.py

  # Scanner PostgreSQL
  python3 PostgreSnopeR.py

  # Scanner Redis
  python3 RedisSnopeR.py

  Attention : ces scripts utilisent des fichiers d'entrée fixes (_*.lst)
  et ne supportent pas les options avancées de la CLI.


================================================================================
6. MODULES DISPONIBLES
================================================================================

6.1 MongoDB

  Détecte :
    - Authentification désactivée
    - Base de données exposées (listDatabases)
    - Version obsolète (< 4.0)
    - Interface HTTP MongoDB (port 28017)

  Exemple de sortie :
    "MongoDB v5.0.12 | NO AUTHENTICATION REQUIRED ⚠️ | 12 databases found"

6.2 MySQL

  Détecte :
    - Comptes par défaut (root:"" , root:root)
    - SSL désactivé
    - Version vulnérable (5.x, 5.1, 5.5)
    - Bases de données sensibles

  Exemple de sortie :
    "MySQL v8.0.33 | accessible as 'root' (default credentials) ⚠️ | 5 databases, 42 tables | SSL DISABLED ⚠️"

6.3 PostgreSQL

  Détecte :
    - Authentification postgres:""
    - Extensions dangereuses (dblink, adminpack, file_fdw)
    - SSL désactivé
    - Versions obsolètes (8.x, 9.0-9.2)

  Exemple de sortie :
    "PostgreSQL v15.2 | authentication required | SSL ENABLED"

6.4 Redis

  Détecte :
    - Aucun mot de passe requis
    - Clés sensibles (password, token, secret)
    - Persistance désactivée
    - Version dangereuse (2.x, 3.x, 4.0)

  Exemple de sortie :
    "Redis | NO AUTHENTICATION REQUIRED ⚠️ | v6.2.7 | 158 keys found | ⚠️ SENSITIVE KEYS DETECTED"

6.5 Elasticsearch

  Détecte :
    - Accès sans authentification
    - Indices sensibles (logs, audit, payment, user)
    - Version vulnérable (Log4Shell : 7.x<17, 6.x<8)
    - Cluster ouvert (création/suppression d'indices possible)

  Exemple de sortie :
    "Elasticsearch v7.10.2 | NO AUTHENTICATION REQUIRED ⚠️ | 24 indices | VULNERABLE VERSION (Log4Shell) ⚠️"

6.6 Kubernetes API

  Détecte :
    - API sans authentification
    - Secrets exposés
    - Pods sensibles (database, mysql, vault)
    - Dashboard exposé (port 8001)

  Exemple de sortie :
    "K8s v1.24.3 | NO AUTHENTICATION REQUIRED ☠️ | 8 namespaces, 47 pods, 3 nodes | ☠️ 12 SECRETS EXPOSED"


================================================================================
7. INTERPRÉTATION DES RÉSULTATS
================================================================================

7.1 Structure des fichiers de sortie

  blackops_scan_20260510_143022.csv
  blackops_scan_20260510_143022.json
  blackops_scan_20260510_143022.html

7.2 Score d'anomalie (0.0 → 1.0)

  Score      Interprétation
  -----      --------------
  0.0 - 0.2  Normal / sécurisé
  0.2 - 0.4  Attention mineure (ex: version un peu ancienne)
  0.4 - 0.7  Anomalie modérée (ex: SSL désactivé)
  0.7 - 0.9  Anomalie grave (ex: authentification désactivée)
  0.9 - 1.0  Critique (ex: secrets exposés, données sensibles accessibles)

7.3 Champs du rapport JSON

  {
    "target_ip": "192.168.1.10",
    "port": 6379,
    "service": "redis",
    "success": true,
    "response_time_ms": 45.2,
    "banner": "Redis | NO AUTHENTICATION REQUIRED ⚠️ | v6.2.7",
    "anomaly_score": 0.85,
    "anomalies": [
      "no_authentication",
      "sensitive_keys_found",
      "default_configuration"
    ],
    "metadata": {
      "version": "6.2.7",
      "keys_count": 158,
      "suspicious_keys": ["auth_token", "session_secret"],
      "memory_usage_mb": 12.4
    },
    "timestamp": "2026-05-10T14:30:22.123456"
  }

7.4 Fichiers logs (logs/blackops.log)

  Format JSON Lines (chaque ligne est un événement JSON) :

  {"level": "INFO", "message": "Scanning 192.168.1.10:6379", "timestamp": "...", "anomaly_score": 0.0}
  {"level": "WARNING", "message": "High anomaly score 0.85 for 192.168.1.10:6379", "anomalies": ["no_authentication"], ...}


================================================================================
8. DOCKER / CONTENEURISATION
================================================================================

8.1 Démarrer l'environnement complet (proxy + cibles de test)

  docker-compose up -d

  Cela démarre :
    - BlackOps scanner
    - Proxy Tor (SOCKS5:9050, HTTP:8118)
    - MongoDB, MySQL, PostgreSQL, Redis, Elasticsearch (cibles vulnérables)

8.2 Lancer un scan depuis Docker

  docker-compose run --rm blackops \
    --ip-list data/ips/test_targets.lst \
    --output docker_scan \
    --deep

8.3 Nettoyer l'environnement

  docker-compose down -v

8.4 Scanner des cibles externes depuis Docker

  # Modifier le fichier data/ips/targets.lst avec vos IPs
  echo "8.8.8.8" > data/ips/targets.lst
  echo "1.1.1.1" >> data/ips/targets.lst

  docker-compose run --rm blackops \
    --ip-list data/ips/targets.lst \
    --output external_scan

8.5 Accès au shell du conteneur

  docker-compose exec blackops /bin/bash

  À l'intérieur du conteneur :
    - Les scripts sont dans /app/
    - Les résultats dans /app/data/output/
    - Les logs dans /app/logs/


================================================================================
9. DÉPANNAGE
================================================================================

9.1 Erreur : "No module named 'blackops'"

  Solution :
    export PYTHONPATH=/chemin/vers/BlackOps
    # ou
    pip install -e .

9.2 Erreur : "Connection refused" avec le proxy

  Vérifier que le proxy SOCKS5 tourne :
    nc -zv 192.168.1.20 9050

  Tester avec Tor directement :
    curl --socks5-hostname 192.168.1.20:9050 https://check.torproject.org/

9.3 Timeouts fréquents

  Augmenter les timeouts dans config.yaml :
    scan:
      timeout: 10
      parallel: 2
      rate_limit: 0.5

9.4 Module Kubernetes ne fonctionne pas

  Vérifier le token et le certificat :
    export K8S_TOKEN="vrai_token"
    export K8S_CA_CERT="/path/to/ca.crt"

  Ou désactiver la vérification SSL (config.yaml) :
    kubernetes:
      verify_ssl: false

9.5 Résultats CSV vides ou incomplets

  Vérifier les permissions d'écriture :
    chmod 755 data/output logs

  Vérifier que les IPs cibles sont accessibles :
    ping -c 2 192.168.1.10

9.6 Erreur BSON decoding (MongoDB)

  C'est normal pour certaines versions récentes de MongoDB.
  Le module essaie d'abord le protocole wire, puis bascule sur pymongo.
  Vérifier la version :
    mongod --version

9.7 L'option --deep ralentit beaucoup le scan

  C'est normal : il construit des baselines statistiques.
  Pour les grands réseaux, limitez le parallélisme :
    --parallel 2 --rate-limit 0.2


================================================================================
10. BONNES PRATIQUES
================================================================================

10.1 Avant de scanner

  ✓ Obtenir une autorisation écrite (pour les réseaux dont vous n'êtes pas propriétaire)
  ✓ Utiliser un proxy (Tor de préférence) pour anonymiser les scans
  ✓ Tester d'abord sur vos propres serveurs
  ✓ Démarrer avec --no-proxy et --deep sur une seule IP de test

10.2 Pendant le scan

  ✓ Surveiller les logs en temps réel : tail -f logs/blackops.log
  ✓ Éviter les scans trop rapides (rate_limit: 1.0 ou moins)
  ✓ Ne pas scanner la même plage plusieurs fois par jour

10.3 Après le scan

  ✓ Archiver les résultats : tar -czf scan_$(date +%Y%m%d).tar.gz data/output/
  ✓ Nettoyer les fichiers sensibles : shred -u data/ips/*.lst
  ✓ Comparer avec les scans précédents (diff)

10.4 Sécurité

  ⚠ Ne jamais committer data/output/ ou logs/ dans Git
  ⚠ Les tokens Kubernetes dans config.yaml doivent rester secrets
  ⚠ Utiliser .gitignore pour exclure :
        data/output/
        logs/
        *.lst
        *.pem
        .env

10.5 Performance

  Pour 1000 IPs avec 6 modules chacun (6000 endpoints) :
    - Temps estimé : 2 à 4 heures (avec --deep)
    - Mémoire : ~500 Mo
    - Disque : ~50 Mo de logs + rapports
    - Recommandation : utiliser screen ou tmux


================================================================================
11. EXEMPLES CONCRETS
================================================================================

11.1 Audit de sécurité interne

  # Étape 1 : Lister les serveurs
  nmap -sL 192.168.1.0/24 | grep -oP '(\d+\.){3}\d+' > data/ips/lan_targets.lst

  # Étape 2 : Scanner sans proxy (réseau interne)
  python3 scripts/blackops-cli.py \
    --ip-list data/ips/lan_targets.lst \
    --output audit_$(date +%Y%m%d) \
    --no-proxy \
    --deep

  # Étape 3 : Générer un rapport HTML
  # (automatiquement généré en sortie)

11.2 Découverte de bases de données exposées sur Internet

  # Étape 1 : Récupérer une liste d'IPs (ex: Shodan, Censys)
  # Supposons que le fichier data/ips/public_dbs.lst existe

  # Étape 2 : Scanner via Tor
  docker-compose up -d tor-proxy
  docker-compose run --rm blackops \
    --ip-list data/ips/public_dbs.lst \
    --output public_scan \
    --deep

  # Étape 3 : Filtrer les résultats critiques
  jq 'select(.anomaly_score > 0.7)' data/output/public_scan.json

11.3 Surveillance continue (cron)

  # Script : /etc/cron.daily/blackops_scan.sh
  #!/bin/bash
  cd /opt/BlackOps
  source venv/bin/activate
  python3 scripts/blackops-cli.py \
    --ip-list /etc/blackops/production_ips.lst \
    --output /var/log/blackops/daily_$(date +%Y%m%d) \
    --deep \
    --format json

  # Alerte si anomalie critique
  if grep -q '"anomaly_score": 0.9' /var/log/blackops/daily_*.json; then
    mail -s "BlackOps Critical Anomaly" admin@example.com < /var/log/blackops/alert.txt
  fi

11.4 Scan d'une seule IP avec tous les modules

  echo "192.168.1.100" > /tmp/single_target.lst

  python3 scripts/blackops-cli.py \
    --ip-list /tmp/single_target.lst \
    --output single_host_audit \
    --deep \
    --verbose

11.5 Test de régression (avant/après patch)

  # Scan avant patch
  python3 scripts/blackops-cli.py -i ips.lst -o before_patch --deep

  # Appliquer les correctifs...

  # Scan après patch
  python3 scripts/blackops-cli.py -i ips.lst -o after_patch --deep

  # Comparer
  diff before_patch.json after_patch.json | grep anomaly_score


================================================================================
12. COMMANDES RAPIDES (CHEAT SHEET)
================================================================================

  # Installation
  pip install -r requirements.txt

  # Scan basique
  python3 scripts/blackops-cli.py -i data/ips/targets.lst -o mon_scan

  # Scan deep + verbose
  python3 scripts/blackops-cli.py -i targets.lst -o scan --deep --verbose

  # Un seul module
  python3 scripts/blackops-cli.py -i targets.lst -m redis -o redis_only

  # Sans proxy (réseau local)
  python3 scripts/blackops-cli.py -i targets.lst --no-proxy -o local_scan

  # Docker
  docker-compose run --rm blackops -i data/ips/test_targets.lst -o docker_scan

  # Afficher les scores d'anomalie
  cat data/output/*.json | jq '.anomaly_score'

  # Lister les IPs critiques
  cat data/output/*.json | jq 'select(.anomaly_score>0.7) | .target_ip'

  # Voir les logs en direct
  tail -f logs/blackops.log | jq '.'

  # Nettoyer les résultats
  rm -rf data/output/* logs/*


================================================================================
13. SUPPORT & INFORMATIONS
================================================================================

  Version actuelle : 1.0
  Date : 2026-05-10
  Auteur : V-Demon (guidé par DeepSeek)

  Dépendances principales :
    - Python 3.9+
    - aiohttp, asyncio
    - pymongo, aiomysql, asyncpg, redis
    - kubernetes, elasticsearch
    - pyyaml, pysocks

  Limitations connues :
    - Le module Kubernetes nécessite un token valide ou un cluster mal configuré
    - Elasticsearch 8.x+ avec sécurité activée bloquera les scans sans auth
    - Le protocole MongoDB wire peut échouer sur les versions très récentes

  Roadmap :
    - Support PostgreSQL via TLS
    - Mode passif (sniffing)
    - Plugin système pour détection de honeypot
    - Dashboard Web temps réel

================================================================================
                             BON SCAN !
================================================================================
