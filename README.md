# TP Couche Réseau L3 — Docker

## Démarrage rapide
```bash
docker compose up -d
docker exec log_generator python generate_logs.py &
docker exec pc_a ping -c3 10.0.0.10
```

## Structure
- `docker-compose.yml` : architecture 7 conteneurs
- `generate_logs.py` : générateur de logs de pannes
- `www/` : page web du serveur Apache
- `logs/` : logs générés au runtime (ignorés par git)
