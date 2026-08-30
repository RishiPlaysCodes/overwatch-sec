# lab/ — safe local test targets

Test the platform without attacking anyone. Everything binds to `127.0.0.1`.

## Quickest (no Docker, stdlib only)
```bash
python3 lab/app.py                                   # starts insecure demo on :8000
python3 vulnscan.py http://127.0.0.1:8000 --profile web --yes
```

## Full lab (Docker)
```bash
cd lab && docker compose up -d
python3 ../vulnscan.py http://127.0.0.1:3000 --profile web --mode deep --yes   # Juice Shop
python3 ../vulnscan.py http://127.0.0.1:8080 --profile web --yes               # DVWA
docker compose down
```

The automated integration test (`tests/test_orchestrator_integration.py`) spins
up an in-process insecure server and asserts the full pipeline works — so CI
never needs Docker or the internet.

> These targets are intentionally vulnerable. Keep them local; never expose them.
