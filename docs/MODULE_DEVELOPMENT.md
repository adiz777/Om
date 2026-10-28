# Module Development Guide — Om 2.0

Every external reconnaissance integration in Om 2.0 follows a strict, uniform contract defined in `om/models/schemas.py` (`ModuleContract`) and executed by `om/modules/registry.py`.

## 1. Common Integration Contract (`ModuleContract`)

To register a new reconnaissance module, add a `ModuleContract` entry to `MODULE_REGISTRY` in `om/modules/registry.py`:

```python
ModuleContract(
    name="exampletool",
    binary_candidates=("exampletool",),
    module_group="webtech",          # Group selectable via --modules
    category="WebTech",              # Subfolder created in session directory
    supported_targets=("domain", "ip"),
    traffic_mode="light-active",     # "passive" | "light-active" | "active"
    estimated_impact="low",          # "low" | "medium" | "high"
    requires_active_auth=False,      # True if --authorize-active is mandatory
    version_args=("--version",),
    apt_hint="sudo apt install -y exampletool",
    alt_hint="pipx install exampletool",
    description="Short description of what the tool observes",
    limitations="Explicit statement of what the tool cannot prove",
)
```

## 2. Safe Command Construction (`build_module_command`)

In `om/modules/registry.py`, add a branch in `build_module_command(...)`:

1. Always return a `list[str]` argument array (never a shell command string).
2. Use `target.host` or `target.base_url` from the validated `TargetSpec`.
3. Where the underlying CLI accepts `--` to terminate options (such as `nmap`), place `"--"` before `target.host`.
4. Respect `config.profile` (`low`, `medium`, `high`) and `config.rate_limit`.

## 3. Output Normalisation (`parse_tool_findings`)

In `om/core/normalizer.py`, add a parser branch in `parse_tool_findings(...)` that returns `list[Finding]`:

- Set `classification` to one of:
  - `raw_observation`
  - `normalised_finding`
  - `inferred_finding`
  - `confirmed_issue` (only when direct protocol evidence confirms a security misconfiguration)
- Set `confidence` to `confirmed`, `inferred`, or `unverified`.
- Include `evidence`, `detail`, and `limitations`.

## 4. Testing Your Module

Add unit and integration tests under `tests/`:

1. Verify command array generation in `tests/unit/test_config_and_normalizer.py`.
2. Verify output parsing and deduplication with sample tool output.
3. Verify execution, timeout, and missing-binary handling using `_create_fake_tool` in `tests/integration/test_orchestrator_and_api.py`.
