# Local iso-prod stack — reproduce the pool leak

Stack minimaliste qui reproduit la prod (4 workers, pool 10/20, schema
complet) sans Traefik / Authelia / vault / OpenCVE / Wazuh. Sert à
identifier le leak de connexions DB en local sous charge.

## Prerequis

- Docker Compose v2 (ou podman compose)
- Python 3.12 + `pip install httpx` pour `seed.py` et `stress.py`

## Lancer

```bash
cd local
cp .env.local.example .env.local
docker compose -f docker-compose.local.yml --env-file .env.local up --build -d
```

L'API ecoute sur `http://127.0.0.1:8000` et PG sur `127.0.0.1:55432`.

Verifier la sante :

```bash
curl http://127.0.0.1:8000/api/v1/health
curl http://127.0.0.1:8000/api/v1/health/pool
```

## Seed + stress

```bash
python local/seed.py        # 10 nodes + 500 packages + 50 CVEs + 5 jobs
python local/stress.py      # martele l'API et imprime pool snapshots
```

`stress.py` affiche toutes les 5s :

- `pool=...` snapshot (`in_use`, `free`, `overflow_used`, `total`)
- `avg_lat=...ms` latence moyenne des requetes
- `counters=...` decompte par status code + erreurs

Si `in_use` croit indefiniment et `free` tombe a 0 → leak reproduit.

## Logs API

```bash
docker compose -f docker-compose.local.yml logs -f api
```

Le `_pool_logger_loop()` emet une ligne `[pool] pid=X in_use=Y free=Z`
toutes les 10s par defaut (DB_POOL_LOG_INTERVAL=10 dans `.env.local`).
WARNING quand `free <= DB_POOL_WARN_FREE` ou overflow > 0.

## Arret + cleanup

```bash
docker compose -f docker-compose.local.yml down -v   # -v supprime aussi le volume PG
```
