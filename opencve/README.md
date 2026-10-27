# OpenCVE v2 — Setup & Operations

## Prerequis

- Docker compose v2
- ~4GB RAM minimum
- Acces Traefik + Authelia

## Installation

```bash
cd /data/container/cmdb/opencve

# 1. Cloner le repo OpenCVE
git clone https://github.com/opencve/opencve.git src

# 2. Copier les configs Django
cp src/web/opencve/conf/.env.example src/web/opencve/conf/.env
cp src/web/opencve/conf/settings.py.example src/web/opencve/conf/settings.py

# 3. Editer la config Django
vim src/web/opencve/conf/.env
#   OPENCVE_DATABASE_URL=postgresql://opencve:<POSTGRES_PASSWORD>@postgres:5432/opencve
#   OPENCVE_SECRET_KEY=<generer ci-dessous>

# 4. Generer les secrets
python3 -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"  # → FERNET_KEY
python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"  # → DJANGO SECRET
openssl rand -hex 24   # → POSTGRES_PASSWORD
openssl rand -hex 16   # → AIRFLOW PASSWORD

# 5. Completer le .env
cp .env.example .env
vim .env
#   POSTGRES_PASSWORD=<mdp genere>
#   _AIRFLOW_WWW_USER_PASSWORD=<mdp genere>
#   AIRFLOW__CORE__FERNET_KEY=<fernet key generee>
#   AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=postgresql+psycopg2://opencve:<POSTGRES_PASSWORD>@postgres:5432/opencve
#   AIRFLOW__CELERY__RESULT_BACKEND=db+postgresql://opencve:<POSTGRES_PASSWORD>@postgres:5432/opencve

# 6. Lancer
docker compose up -d

# 7. Attendre que airflow-init finisse
docker logs -f opencve_airflow_init

# 8. Creer le compte admin Django
docker exec -it opencve_web python manage.py createsuperuser

# 9. Activer le DAG CVE (import initial NVD = 15-30min)
docker exec -it opencve_airflow_web airflow dags unpause opencve
```

## Acces

- UI : https://opencve.example.com (via Traefik + Authelia)
- Airflow : interne uniquement (port 8080 non expose)

---

## Commandes OpenCVE

### Stack management

```bash
# Depuis /data/container/cmdb (ou make)
make opencve-up          # Lancer la stack OpenCVE
make opencve-down        # Arreter la stack OpenCVE
make opencve-logs        # Logs en temps reel

# Ou directement
cd opencve && docker compose up -d
cd opencve && docker compose down
cd opencve && docker compose ps
```

### Airflow — DAGs

```bash
# Lister les DAGs
docker exec opencve_airflow_web airflow dags list

# Activer/desactiver le pipeline CVE
docker exec opencve_airflow_web airflow dags unpause opencve
docker exec opencve_airflow_web airflow dags pause opencve

# Forcer un run du DAG maintenant
docker exec opencve_airflow_web airflow dags trigger opencve

# Statut des derniers runs
docker exec opencve_airflow_web airflow dags list-runs -d opencve

# Statut des taches en cours
docker exec opencve_airflow_web airflow tasks list opencve
```

### Django admin

```bash
# Creer un compte admin
docker exec -it opencve_web python manage.py createsuperuser

# Shell Django (debug)
docker exec -it opencve_web python manage.py shell

# Collecter les fichiers statiques (apres update)
docker exec opencve_web python manage.py collectstatic --noinput

# Migrations Django
docker exec opencve_web python manage.py migrate
```

### Base de donnees

```bash
# Shell psql
docker exec -it opencve_postgres psql -U opencve -d opencve

# Nombre de CVEs dans OpenCVE
docker exec opencve_postgres psql -U opencve -d opencve -c "SELECT COUNT(*) FROM opencve_cve;"

# Nombre de vendors/produits
docker exec opencve_postgres psql -U opencve -d opencve -c "SELECT COUNT(*) FROM opencve_vendor;"
docker exec opencve_postgres psql -U opencve -d opencve -c "SELECT COUNT(*) FROM opencve_product;"

# Dump
docker exec opencve_postgres pg_dump -U opencve opencve > opencve_backup.sql
```

### Logs et debug

```bash
# Logs par service
docker logs -f opencve_web              # Django/Gunicorn
docker logs -f opencve_airflow_worker   # Airflow worker (import CVE)
docker logs -f opencve_airflow_sched    # Airflow scheduler
docker logs -f opencve_nginx            # Nginx proxy
docker logs -f opencve_postgres         # PostgreSQL

# Sante des containers
docker compose ps
docker inspect opencve_web --format '{{.State.Health.Status}}'
```

---

## Sync CMDB

Deux scripts synchronisent les CVEs depuis OpenCVE vers la CMDB.

### Sync incremental (cron, automatique)

Le container `cmdb_sync_opencve` tourne en boucle (toutes les heures) et recupere les CVEs recentes.

```bash
# Sync manuel (dernieres 24h)
make opencve-sync

# Ou directement
docker exec cmdb_sync_opencve python3 /app/sync_opencve.py --hours 24

# Fenetre custom
docker exec cmdb_sync_opencve python3 /app/sync_opencve.py --hours 48
```

Limite : max 2000 CVEs par run (200 pages × 10 CVEs/page OpenCVE v2).

### Import initial (one-shot)

Pour peupler la CMDB lors de la premiere installation ou apres un reset.

```bash
# Import complet, sans filtre
make opencve-full

# Ou directement avec options
docker exec cmdb_sync_opencve python3 /app/sync_opencve_full.py

# Critical seulement
docker exec cmdb_sync_opencve python3 /app/sync_opencve_full.py --min-severity critical

# High + critical, derniers 60 jours
docker exec cmdb_sync_opencve python3 /app/sync_opencve_full.py --min-severity high --hours 1480

# Max 100k CVEs, reprendre apres interruption
docker exec cmdb_sync_opencve python3 /app/sync_opencve_full.py --limit 100000 --resume

# Test : 100 CVEs
docker exec cmdb_sync_opencve python3 /app/sync_opencve_full.py --limit 100
```

| Option | Description |
|--------|-------------|
| `--min-severity critical\|high\|medium\|low` | Seuil minimum (ex: `high` = high + critical) |
| `--hours N` | Fenetre temporelle (740 ~30j, 1480 ~60j, 0 = tout) |
| `--limit N` | Nombre max de CVEs a importer |
| `--resume` | Skip les CVEs deja importees |
| `--workers N` | Threads paralleles pour le detail fetch (defaut: 4) |

---

## Mise a jour

```bash
cd opencve/src && git pull && cd ..
docker compose build
docker compose up -d
```

## Architecture

```
Traefik → nginx (static + proxy) → Django/Gunicorn (:8000)
                                         ↓
Airflow (scheduler + worker) ←→ PostgreSQL 15
                              ←→ Redis
```

8 containers : postgres, redis, airflow-init (one-shot), airflow-webserver,
airflow-scheduler, airflow-worker, webserver (Django), nginx

Reseau : `opencve_internal` (bridge interne) + `observability_net` (webserver accessible depuis cmdb_sync_opencve sur 172.20.0.26:8000)
