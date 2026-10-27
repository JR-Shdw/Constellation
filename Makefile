# CMDB — Makefile
# Usage: make <target>

.PHONY: help up down build logs restart ps db-shell db-backup api-logs lint test secrets clean \
       deploy sync migrate deploy-sync deploy-restart scan-images \
       opencve-up opencve-down opencve-logs opencve-sync opencve-full \
       opencve-ps opencve-dag-start opencve-dag-stop opencve-dag-trigger \
       opencve-dag-status opencve-admin opencve-db-shell opencve-db-count \
       opencve-build wazuh-sync collect collect-trivy collect-backup collect-misconf \
       collect-drift cron-install cron-remove cron-list vault-status \
       secrets-baseline hooks-install hooks-uninstall \
       deps-lock deps-audit deps-update

COMPOSE := docker compose
COMPOSE_OPENCVE := docker compose -f opencve/docker-compose.yml

# ── Aide ─────────────────────────────────────────────────────

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

# ── Stack CMDB ───────────────────────────────────────────────

up: ## Lance la stack CMDB (postgres + api + frontend)
	$(COMPOSE) up -d

down: ## Arrete la stack CMDB
	$(COMPOSE) down

build: ## Build les images (api + frontend)
	$(COMPOSE) build

restart: ## Restart la stack
	$(COMPOSE) restart

logs: ## Logs de tous les services
	$(COMPOSE) logs -f --tail=50

ps: ## Statut des services
	$(COMPOSE) ps

api-logs: ## Logs de l'API uniquement
	$(COMPOSE) logs -f --tail=100 api

db-shell: ## Shell psql dans le container postgres
	$(COMPOSE) exec postgres psql -U $${POSTGRES_USER:-cmdb_user} -d $${POSTGRES_DB:-cmdb}

db-backup: ## Dump de la base PostgreSQL
	@mkdir -p backups
	$(COMPOSE) exec postgres pg_dump -U $${POSTGRES_USER:-cmdb_user} $${POSTGRES_DB:-cmdb} \
		| gzip > backups/cmdb-$$(date +%Y%m%d-%H%M%S).sql.gz
	@echo "Dump: backups/cmdb-$$(date +%Y%m%d-%H%M%S).sql.gz"

# ── Stack OpenCVE ────────────────────────────────────────────

opencve-up: ## Lancer la stack OpenCVE
	$(COMPOSE_OPENCVE) up -d

opencve-down: ## Arreter la stack OpenCVE
	$(COMPOSE_OPENCVE) down

opencve-ps: ## Statut des containers OpenCVE
	$(COMPOSE_OPENCVE) ps

opencve-logs: ## Logs OpenCVE (tous les services)
	$(COMPOSE_OPENCVE) logs -f --tail=50

opencve-build: ## Rebuild les images OpenCVE (apres git pull src)
	$(COMPOSE_OPENCVE) build

opencve-admin: ## Creer un compte admin Django OpenCVE
	docker exec -it opencve_web python manage.py createsuperuser

opencve-db-shell: ## Shell psql dans la DB OpenCVE
	docker exec -it opencve_postgres psql -U opencve -d opencve

opencve-db-count: ## Compter les CVEs/vendors/produits dans OpenCVE
	@echo "=== OpenCVE database ==="
	@docker exec opencve_postgres psql -U opencve -d opencve -t -c "SELECT 'CVEs: ' || COUNT(*) FROM opencve_cve;"
	@docker exec opencve_postgres psql -U opencve -d opencve -t -c "SELECT 'Vendors: ' || COUNT(*) FROM opencve_vendor;"
	@docker exec opencve_postgres psql -U opencve -d opencve -t -c "SELECT 'Products: ' || COUNT(*) FROM opencve_product;"

opencve-dag-start: ## Activer le DAG OpenCVE (import CVEs)
	docker exec opencve_airflow_web airflow dags unpause opencve

opencve-dag-stop: ## Desactiver le DAG OpenCVE
	docker exec opencve_airflow_web airflow dags pause opencve

opencve-dag-trigger: ## Forcer un run du DAG maintenant
	docker exec opencve_airflow_web airflow dags trigger opencve

opencve-dag-status: ## Statut des derniers runs du DAG
	docker exec opencve_airflow_web airflow dags list-runs -d opencve

# ── Sync CMDB ←→ sources ────────────────────────────────────

opencve-sync: ## Sync OpenCVE -> CMDB (incremental, dernieres 24h)
	$(COMPOSE) exec sync-opencve python3 /app/sync_opencve.py --hours 24

opencve-full: ## Import initial OpenCVE -> CMDB (toutes les CVEs, resume)
	$(COMPOSE) exec sync-opencve python3 /app/sync_opencve_full.py --resume

wazuh-sync: ## Sync Wazuh -> CMDB (CVEs + SCA)
	$(COMPOSE) exec sync-wazuh python3 /app/sync_wazuh.py

# Ansible playbooks — separate repo: youruser/cmdb_collect
# Clone: git clone ssh://git@gitea.example.com:222/youruser/cmdb_collect.git ansible
ANSIBLE_DIR ?= ansible

collect: ## Collecte inventaire Ansible (tous les hosts)
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventory/hosts.ini playbooks/collect.yml

collect-trivy: ## Scan Trivy CVE via Ansible (tous les hosts)
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventory/hosts.ini playbooks/scan_trivy.yml

collect-backup: ## Collecte logs backup Restic via Ansible
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventory/hosts.ini playbooks/collect_backup_logs.yml

collect-misconf: ## Scan misconfigurations Trivy via Ansible
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventory/hosts.ini playbooks/scan_misconf.yml

collect-drift: ## Detection drift configuration via Ansible
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventory/hosts.ini playbooks/check_drift.yml

# ── Cron setup ──────────────────────────────────────────────

cron-install: ## Installer les crons Ansible (collect, trivy, misconf, drift, backup)
	@echo "Installing CMDB Ansible cron jobs..."
	@(crontab -l 2>/dev/null | grep -v 'cmdb.*ansible-cron'; \
	  echo "# CMDB Ansible — collecte inventaire (daily 02:17)"; \
	  echo "17 2 * * * /home/shdw/dev/tools/cmdb/scripts/ansible-cron.sh collect.yml"; \
	  echo "# CMDB Ansible — scan Trivy CVE (daily 03:07)"; \
	  echo "7 3 * * * /home/shdw/dev/tools/cmdb/scripts/ansible-cron.sh scan_trivy.yml"; \
	  echo "# CMDB Ansible — scan misconfigurations (daily 04:23)"; \
	  echo "23 4 * * * /home/shdw/dev/tools/cmdb/scripts/ansible-cron.sh scan_misconf.yml"; \
	  echo "# CMDB Ansible — drift detection (daily 05:11)"; \
	  echo "11 5 * * * /home/shdw/dev/tools/cmdb/scripts/ansible-cron.sh check_drift.yml"; \
	  echo "# CMDB Ansible — collecte backup logs (daily 06:43)"; \
	  echo "43 6 * * * /home/shdw/dev/tools/cmdb/scripts/ansible-cron.sh collect_backup_logs.yml"; \
	) | crontab -
	@echo "Done. Verify with: crontab -l"

cron-remove: ## Supprimer les crons Ansible CMDB
	@crontab -l 2>/dev/null | grep -v 'cmdb.*ansible-cron' | grep -v '# CMDB Ansible' | crontab -
	@echo "CMDB crons removed."

cron-list: ## Afficher les crons CMDB actifs
	@crontab -l 2>/dev/null | grep -E '(CMDB|ansible-cron)' || echo "No CMDB crons found"

scan-images: ## Scan Trivy des images CMDB + push CVEs vers l'API
	bash scripts/scan-images.sh

scan-images-push: ## Re-push les rapports Trivy existants sans re-scanner
	bash scripts/scan-images.sh --push-only

# ── Deploy (idempotent) ────────────────────────────────────

deploy: ## Deploy complet (sync + migrate + build + restart + healthcheck)
	bash scripts/deploy.sh

sync: ## Sync fichiers vers /data/container/cmdb (sans restart)
	bash scripts/deploy.sh --sync-only

migrate: ## Appliquer le schema SQL (idempotent, sans restart)
	bash scripts/deploy.sh --migrate-only

deploy-restart: ## Restart sans rebuild (rapide)
	bash scripts/deploy.sh --restart-only

# ── Dev / CI ─────────────────────────────────────────────────

lint: ## Lint du code API (ruff)
	ruff check api/
	ruff format --check api/

lint-fix: ## Lint + auto-fix
	ruff check --fix api/
	ruff format api/

test: ## Lance les tests pytest
	pytest tests/ -v --tb=short

# ── Pre-commit + secrets baseline ────────────────────────────

hooks-install: ## Active les git hooks (Option B — shell + Docker fallback)
	@git config core.hooksPath scripts/git-hooks
	@echo "[hooks] core.hooksPath = scripts/git-hooks"
	@echo "[hooks] alternative (Option A): pip install pre-commit && pre-commit install"

hooks-uninstall: ## Desactive les git hooks (revient au .git/hooks/ par defaut)
	@git config --unset core.hooksPath 2>/dev/null || true
	@echo "[hooks] core.hooksPath unset (default .git/hooks/ restored)"

secrets-baseline: ## Regenere .secrets.baseline (detect-secrets en container)
	@. ./versions.env && \
	docker run --rm -v "$$PWD:/work" -w /work python:3.12-slim sh -c " \
		apt-get update -qq >/dev/null && apt-get install -qq -y git >/dev/null && \
		pip install --quiet detect-secrets==$$DETECT_SECRETS_VERSION && \
		git config --global --add safe.directory /work && \
		detect-secrets scan \
			--baseline .secrets.baseline \
			--exclude-files '\.git/.*' \
			--exclude-files 'env\.example' \
			--exclude-files '\.env' \
			--exclude-files 'tests/.*' \
			--exclude-files '.*\.pyc' \
			--exclude-files '\.venv/.*' \
			--exclude-files '\.ruff_cache/.*' \
			--exclude-files '\.pytest_cache/.*' \
			--exclude-files '\.coverage' \
			--exclude-files '.*\.lock' \
			--exclude-files 'requirements-dev\.txt' \
		"
	@echo "[OK] .secrets.baseline regenere — relire avec 'git diff .secrets.baseline'"
	@echo "     audit interactif d'un finding : detect-secrets audit .secrets.baseline"

# ── Supply-chain (SLSA) — deps lock + audit ──────────────────
# Bump workflow: edit a version in api/requirements.txt, requirements-dev.in,
# or tools/requirements.in, then run `make deps-update` (rehash + scan), review
# the *.lock diff, and commit. See SUPPLY_CHAIN.md.

PIP_PIN ?= 26.1.2

deps-lock: ## Rehash : recompile les lockfiles (--generate-hashes) depuis *.in / requirements.txt
	@. ./versions.env && docker run --rm -v "$$PWD:/work" -w /work python:$$PYTHON_VERSION sh -c " \
		pip install --no-cache-dir -q 'pip==$(PIP_PIN)' pip-tools && \
		pip-compile --generate-hashes --quiet --output-file=api/requirements.lock api/requirements.txt && \
		pip-compile --generate-hashes --quiet --strip-extras --output-file=requirements-dev.txt requirements-dev.in && \
		pip-compile --generate-hashes --quiet --output-file=tools/requirements.lock tools/requirements.in"
	@echo "[OK] lockfiles regeneres — review 'git diff api/requirements.lock requirements-dev.txt tools/requirements.lock'"

deps-audit: ## Scan : pip-audit des lockfiles (echoue si vuln connue)
	@. ./versions.env && docker run --rm -v "$$PWD:/work" -w /work python:$$PYTHON_VERSION sh -c " \
		pip install --no-cache-dir -q 'pip==$(PIP_PIN)' pip-audit && \
		echo '[audit] api/requirements.lock'   && pip-audit -r api/requirements.lock   && \
		echo '[audit] requirements-dev.txt'    && pip-audit -r requirements-dev.txt    && \
		echo '[audit] tools/requirements.lock' && pip-audit -r tools/requirements.lock"
	@echo "[OK] aucune vuln connue dans les deps lockees"

deps-update: deps-lock deps-audit ## Bump workflow : rehash puis scan (apres edition d'une version)
	@echo "[OK] deps re-lock + scan verts — review le diff et commit les *.lock"

# ── Secrets ──────────────────────────────────────────────────

secrets: ## Genere les secrets dans .env
	@if [ -f .env ]; then echo ".env existe deja"; exit 1; fi
	@cp env.example .env
	@PG_PASS=$$(openssl rand -hex 24) && \
		API_KEY=$$(openssl rand -hex 32) && \
		TOKEN=$$(openssl rand -hex 32) && \
		HMAC_KEY=$$(openssl rand -hex 32) && \
		sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$$PG_PASS/" .env && \
		sed -i "s/^API_SECRET_KEY=.*/API_SECRET_KEY=$$API_KEY/" .env && \
		sed -i "s/^COLLECT_TOKEN=.*/COLLECT_TOKEN=$$TOKEN/" .env && \
		sed -i "s/^TOKEN_HMAC_KEY=.*/TOKEN_HMAC_KEY=$$HMAC_KEY/" .env
	@echo ".env genere avec secrets aleatoires"
	@echo "COLLECT_TOKEN a copier dans le vault Ansible :"
	@grep COLLECT_TOKEN .env

# ── rhorizon ──────────────────────────────────────────────────

vault-status: ## Statut du vault (sealed/unsealed)
	@VAULT_URL=$$(grep -m1 VAULT_URL .env 2>/dev/null | cut -d= -f2-); \
	if [ -z "$$VAULT_URL" ]; then echo "VAULT_URL not set in .env"; exit 1; fi; \
	curl -sf "$$VAULT_URL/api/v1/vault/status" | python3 -m json.tool || echo "Vault unreachable"

# ── Nettoyage ────────────────────────────────────────────────

publish: ## Publier une version sanitizee sur GitHub
	GITHUB_REPO=$${GITHUB_REPO:?set GITHUB_REPO} bash scripts/publish-github.sh

clean: ## Supprime volumes et images orphelines
	$(COMPOSE) down -v --remove-orphans
	docker image prune -f
