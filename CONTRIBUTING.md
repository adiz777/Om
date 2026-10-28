# Contributing to Om 2.0

Thank you for your interest in contributing to **Om 2.0** by **Major_ADI**!

## 1. Ground Rules

- **Defensive & Authorised Scope Only:** We do not accept modules that perform automated exploitation, credential stuffing, denial-of-service, persistence, or security-control evasion.
- **Safety First:** Never use `shell=True`, never auto-install packages with `sudo`, and always escape untrusted output in reports and UI views.
- **Evidence Accuracy:** Separate raw observations, normalised findings, inferred findings, and confirmed issues. Never invent CVEs or severity scores without direct protocol evidence.

## 2. Development Setup

```bash
git clone https://github.com/adiz777/Om.git
cd Om
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 3. Quality Gates Before Submitting a Pull Request

Run all checks locally before opening a PR:

```bash
# 1. Lint and static security checks
ruff check om tests

# 2. Unit, integration, and API tests
pytest -v

# 3. Shell wrapper syntax check
bash -n Om.sh om_recon.sh
```

See [`docs/MODULE_DEVELOPMENT.md`](docs/MODULE_DEVELOPMENT.md) for instructions on adding a new reconnaissance tool adapter.
