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

## 4. Proposed Fix (Awaiting Review)

To prevent legitimate runtime startup overhead from masking real application-level security violations:

1. **Exclude System & Python Runtime Internals from Application File Tracking:**
   In `RuntimeCapture._parse_file()` (or in `_compare_file()`):
   - Ignore paths under standard system and library trees:
     - `/usr/lib/python*`, `/usr/include`, `/usr/local/lib/python*`
     - `/etc/ld.so.*`, `/lib/*`, `/lib64/*`
     - The staged dependency cache `/workspace/.deps/`
     - Python internal bytecode caches (`__pycache__`, `*.pyc`, `*.pyo`)
2. **Preserve Sensitivity Checking:**
   - Any access to sensitive paths (e.g. `/etc/passwd`, `/etc/shadow`, `~/.ssh`, `~/.aws`, `.env`, tokens/credentials) will still be captured and flagged regardless of prefix.
3. **Application Scope Focus:**
   - Only file reads and writes directed at user files, project source code, configuration files, and arbitrary filesystem destinations will be compared against declared claims.
