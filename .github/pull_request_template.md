## Summary
Briefly describe the changes introduced in this pull request.

## Verification Checklist
- [ ] `ruff check om tests` passes with zero warnings
- [ ] `pytest -v` passes all unit, integration, and API tests
- [ ] No `shell=True` subprocess calls or automatic `sudo` package installations introduced
- [ ] Untrusted target/tool output is escaped in HTML reports and dashboard views
- [ ] Documentation (`README.md`, `CHANGELOG.md`, or `docs/`) updated if CLI flags or API endpoints changed
