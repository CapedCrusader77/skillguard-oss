# Validation Notes: Runtime Verification Smoke Benchmark

## 1. Target Repository Inspected
- **Repository:** [`modelcontextprotocol/quickstart-resources`](https://github.com/modelcontextprotocol/quickstart-resources)
- **Target Entrypoint Selected:** `weather-server-python/weather.py`
- **Benchmark Observation:**
  - `status`: `completed`
  - `runtime_status`: `completed`
  - `verification_available`: `true`
  - `mismatch_count`: `910`
  - `mismatch_types`: `["unexpected_read", "unexpected_write"]`
  - `trust_delta`: `-12096`
  - `verification_score`: `0`

---

## 2. Manual Source Code Audit (`weather.py`)

The detected entrypoint is the official Model Context Protocol sample server located at `weather-server-python/weather.py`.

### Functions Implemented:
1. `make_nws_request(url: str)`: Helper using `httpx2.AsyncClient()` to issue an HTTPS GET request to `https://api.weather.gov` with `User-Agent: weather-app/1.0` and `Accept: application/geo+json`.
2. `get_alerts(state: str) -> Alerts`: Queries `https://api.weather.gov/alerts/active/area/{state}` and returns weather alerts parsed with Pydantic.
3. `get_forecast(latitude: float, longitude: float) -> Forecast`: Queries the NWS grid endpoint and forecast URL, returning period forecasts parsed with Pydantic.
4. `main()`: Calls `mcp.run(transport="stdio")`.

### Application Filesystem Activity:
- **Application file reads:** None. The script never invokes `open()`, `read()`, or any file I/O APIs.
- **Application file writes:** None. No file creation or modification is attempted by the server logic.
- **Application network activity:** Connects strictly to `api.weather.gov:443`.

---

## 3. Finding Classification: False Positive

The 910 findings attributing `unexpected_read` and `unexpected_write` to this repository are a **False Positive**.

### Root Cause Analysis:
1. **Unfiltered Runtime & Interpreter Trace:**
   - `strace` captures all low-level syscalls (`openat`, `open`, `creat`) across the entire Python process lifecycle.
   - When Python initializes, it opens hundreds of runtime files:
     - Dynamic linker & loader: `/etc/ld.so.cache`, `/lib/x86_64-linux-gnu/*`
     - Python standard library: `/usr/lib/python3.12/*`, encodings, codecs, importlib, zipimport
     - Third-party packages: `/workspace/.deps/*` (`pydantic`, `mcp`, `httpx2`, `anyio`, `sniffio`, etc.)
     - Bytecode compilation: Python writes bytecode cache files to `__pycache__/*.pyc` when importing uncompiled modules, which `_parse_file()` classifies as `unexpected_write`.
2. **Undeclared Base Filesystem Claims:**
   - The repository's documentation does not declare filesystem read or write access (the server's purpose is purely an API gateway to weather data).
   - Because `claims.filesystem.state` is undeclared/unknown, `_compare_file()` flags every single opened system library file as an unexpected filesystem read, and every `.pyc` creation as an unexpected filesystem write.
   - Each flagged file access carries a negative weight (e.g. 12 for `unexpected_read`, 40 for `unexpected_write`), totaling -12,096 and dropping the verification score to 0.

---

## 4. Implemented Fix & Scoring Calibration

To prevent legitimate runtime startup overhead from masking real application-level security violations:

1. **Excluded System & Python Runtime Internals from Application File Tracking:**
   In `RuntimeCapture._parse_file()`:
   - Filtered out standard system library trees (`/opt/`, `/usr/`, `/lib/`, `/lib64/`, `/etc/ld.so*`, `/etc/ssl/`, `/etc/resolv.conf`, etc.).
   - Filtered out staged dependency packages (`/workspace/.deps/`).
   - Filtered out bytecode caches and package metadata (`__pycache__`, `*.pyc`, `*.dist-info`, `*.egg-info`).
   - Filtered out bubblewrap sandbox wrapper trace files and `bwrap` `/newroot` pivot mounts.
   - Filtered out `O_DIRECTORY` directory traversal/probing and base workspace entries from sys.path.
2. **Preserved Sensitivity Checking:**
   - Any access to sensitive paths (e.g. `/.ssh`, `/.aws`, `/.env`, `id_rsa`, `passwd`, `shadow`, `secret`, `token`) is never filtered and always flagged.
3. **Application Scope Focus:**
   - Real application file operations targeting user files, configuration data, or external filesystem locations are tracked and compared against declared claims.

---

## 5. Post-Fix Benchmark Confirmation (Clean True Negative)

Following deployment of the fix in CI (Run #35428934638):
- **Repository:** `modelcontextprotocol/quickstart-resources` (`weather-server-python/weather.py`)
- **Execution Status:** `completed`
- **Verification Available:** `true`
- **Mismatches Observed:** `0`
- **Trust Delta:** `0`
- **Verification Score:** `100` (Verdict: `Behavior matches declared claims`)

The detector now accurately identifies `quickstart-resources` as a clean, compliant MCP tool, while preserving full detection capabilities for non-compliant or malicious behavior.
