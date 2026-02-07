# API Security Analysis: Meshtastic Site Planner

**Date:** 2026-02-07
**Scope:** Attack surface analysis from the perspective of an API consumer
**Application:** FastAPI-based RF coverage prediction service (SPLAT! backend)

---

## Executive Summary

This analysis examines the Meshtastic Site Planner API from the perspective of a malicious or misbehaving API consumer. The application exposes three HTTP endpoints (`POST /predict`, `GET /status/{task_id}`, `GET /result/{task_id}`) with **no authentication, no authorization, and no rate limiting**. The most impactful attack vectors are resource exhaustion via computationally expensive predictions, task ID enumeration to access other users' results, and abuse of the CORS configuration. Several issues stem from the application's implicit trust of all incoming requests.

### Risk Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 2 | Resource exhaustion DoS, no authentication |
| High | 4 | Task enumeration (IDOR), CORS misconfiguration, error information leakage, Redis exposure |
| Medium | 4 | Unbounded background tasks, Content-Disposition injection, missing security headers, container runs as root |
| Low | 3 | Unused dependencies, SPLAT! stdout/stderr leakage, HTTP-only CORS origin |

---

## CRITICAL Findings

### C1. No Authentication or Authorization

**Affected endpoints:** All (`/predict`, `/status/{task_id}`, `/result/{task_id}`)
**File:** `app/main.py:77-161`

The API has zero authentication. Any client that can reach the service can:
- Submit unlimited prediction jobs
- Query the status of any task
- Download any completed result

There are no API keys, tokens, session cookies, OAuth flows, or any other identity mechanism. The application cannot distinguish between legitimate users and attackers, making every other vulnerability in this report more exploitable.

**Attack scenario:** An attacker writes a simple script to submit hundreds of concurrent `POST /predict` requests, consuming all server resources (12 GB memory limit, CPU, disk I/O for terrain tiles, and S3 bandwidth).

**Recommendation:** Implement at minimum an API key mechanism or token-based authentication. Even a simple shared secret in a request header would provide basic access control and enable per-client rate limiting.

---

### C2. Denial of Service via Compute Exhaustion

**Affected endpoint:** `POST /predict`
**Files:** `app/main.py:77-97`, `app/services/splat.py:123-250`

Each prediction request triggers a computationally expensive chain:
1. Downloads terrain tiles from S3 (network I/O + disk writes)
2. Decompresses `.hgt.gz` tiles with gzip
3. Optionally resamples terrain data with rasterio
4. Converts tiles to SDF format via subprocess (`srtm2sdf`)
5. Executes the SPLAT! binary via subprocess (CPU-intensive RF propagation modeling)
6. Reads PPM output, parses KML, generates GeoTIFF with rasterio + matplotlib
7. Stores result in Redis (memory)

**No rate limiting exists anywhere in the stack.** An attacker can flood `POST /predict` with maximum-radius (500 km) requests targeting different geographic coordinates (forcing cache misses on terrain tiles). Each request can:
- Download dozens of 1-degree terrain tiles from S3
- Spawn multiple subprocesses
- Consume significant CPU and memory

The `BackgroundTasks` mechanism in FastAPI runs tasks in a thread pool with no concurrency cap. An attacker can queue thousands of jobs that will all compete for resources simultaneously.

**Worst-case parameters for maximum damage:**
```json
{
  "lat": 0.0, "lon": 0.0,
  "radius": 500000,
  "high_resolution": true,
  "tx_power": 1, "tx_height": 1, "tx_gain": 0,
  "rx_height": 1, "rx_gain": 0, "signal_threshold": -1,
  "frequency_mhz": 905
}
```

While `high_resolution` is currently force-disabled (`splat.py:143`), the `radius` of 500 km is still honored and creates a large computational workload.

**Compounding factor:** The `docker-compose.yml:13` sets `mem_limit: 12G`. With enough concurrent tasks, the container will hit this limit and start getting OOM-killed, causing cascading failures.

**Recommendation:**
- Implement rate limiting (e.g., per-IP using a middleware like `slowapi`)
- Add a global concurrency limit on background tasks (e.g., a semaphore or task queue like Celery with bounded workers)
- Consider a request queue with position tracking instead of immediate background execution

---

## HIGH Findings

### H1. Insecure Direct Object Reference (IDOR) — Task ID Enumeration

**Affected endpoints:** `GET /status/{task_id}`, `GET /result/{task_id}`
**File:** `app/main.py:99-161`

Task IDs are UUIDv4 strings (`uuid4()`). While UUIDv4 has a large keyspace (2^122), there are several weaknesses:

1. **No ownership verification:** Any client can access any task's status and result. If an attacker obtains a valid task ID (via network sniffing, logs, shared URLs, or shoulder surfing), they can download the GeoTIFF result.

2. **Task ID logged in plaintext:** Task IDs are written to application logs (`main.py:63,67,70,72,116,147,160`). If logs are exposed (via misconfigured log aggregation, debug endpoints, or container stdout), task IDs are compromised.

3. **404 vs. 200 oracle:** The `/status/{task_id}` endpoint returns 404 for non-existent tasks and 200 for existing ones. This is a boolean oracle that confirms whether a UUID is valid, which could be used for targeted brute-force if the UUID generation were ever weakened.

4. **No `task_id` format validation:** The `task_id` path parameter is accepted as an arbitrary string. While this doesn't cause direct harm with the current Redis-based storage, it means arbitrary strings are used as Redis keys: `redis_client.get(f"{task_id}:status")`. An attacker could probe Redis by sending specially crafted task IDs.

**Recommendation:**
- Add ownership tokens: return a secret `access_token` alongside `task_id` from `/predict`, and require it for `/status` and `/result`
- Validate that `task_id` matches UUID format before querying Redis
- Consider signing task IDs with HMAC to prevent forgery

---

### H2. CORS Misconfiguration

**File:** `app/main.py:38-44`

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:*/", "http://site.meshtastic.org"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Multiple issues:

1. **Broken wildcard pattern:** `"http://localhost:*/"` is not a valid CORS origin pattern. The `CORSMiddleware` in Starlette does not support glob patterns in origin strings — it performs exact string matching. This means requests from `http://localhost:5173` will **not** match this pattern, and the CORS header will not be set for the development frontend. However, Starlette's CORS middleware falls back to reflecting the `Origin` header if `allow_credentials=True` and the origin partially matches — this behavior varies by version and could unexpectedly allow unintended origins.

2. **HTTP-only origin:** `"http://site.meshtastic.org"` uses HTTP, not HTTPS. This means CORS will not permit requests from the HTTPS version of the site. If the production site uses HTTPS (which the nginx-proxy with certs suggests), the legitimate frontend will be blocked while the insecure HTTP origin is allowed.

3. **`allow_credentials=True` with permissive origins:** When credentials are allowed, browsers send cookies and auth headers cross-origin. Combined with a permissive origin list, this could allow a malicious page to make authenticated cross-origin requests.

4. **`allow_methods=["*"]` and `allow_headers=["*"]`:** Allows all HTTP methods (including DELETE, PATCH, PUT) and all headers. While no destructive endpoints exist today, this violates the principle of least privilege and opens the door for future misuse.

**Recommendation:**
- Use explicit, exact origins: `["http://localhost:5173", "https://site.meshtastic.org"]`
- Only allow methods that are actually used: `["GET", "POST"]`
- Only allow headers that are actually needed: `["Content-Type"]`
- Reconsider whether `allow_credentials` is actually needed (the API has no auth, so likely not)

---

### H3. Error Information Leakage

**Files:** `app/main.py:71-74`, `app/services/splat.py:233-236,249-250`

When a prediction task fails, the full Python exception string is stored in Redis and returned to the API consumer:

```python
# main.py:74
redis_client.setex(f"{task_id}:error", 3600, str(e))

# main.py:158
error = redis_client.get(f"{task_id}:error")
return JSONResponse({"status": "failed", "error": error.decode("utf-8")})
```

The exceptions originate from `splat.py` and include:

```python
# splat.py:234-235 — SPLAT! subprocess failure
raise RuntimeError(
    f"SPLAT! execution failed with return code {splat_result.returncode}\n"
    f"Stdout: {splat_result.stdout}\nStderr: {splat_result.stderr}"
)

# splat.py:250 — generic coverage prediction error
raise RuntimeError(f"Error during coverage prediction: {e}")
```

This leaks:
- Internal file paths (e.g., `/app/splat/splat`, temporary directory paths)
- SPLAT! binary stdout/stderr output (potentially revealing system information)
- Python stack trace details
- Redis connection details in connection errors
- S3 bucket/key paths on download failures

**Attack scenario:** An attacker submits intentionally malformed (but Pydantic-valid) requests designed to trigger edge-case failures in SPLAT!, then reads the error response to map the server's internal file structure, binary versions, and infrastructure.

**Recommendation:**
- Return generic error messages to the client (e.g., `"Prediction failed. Please try again."`)
- Log detailed errors server-side only
- Never include subprocess stdout/stderr in client-facing responses

---

### H4. Redis Exposed Without Authentication

**File:** `docker-compose.yml:24-30`

```yaml
redis:
  image: redis:latest
  ports:
    - 6379:6379
  command: [redis-server]
```

Redis is exposed on port 6379 with **no password, no TLS, and no ACLs**. While the `networks` configuration limits this to the Docker network, the `ports: - 6379:6379` directive **also publishes the port to the host machine**, making it accessible to any process on the host and potentially to the network if the host has open firewall rules.

An attacker who can reach port 6379 can:
- Read all task results (GeoTIFF files) stored in Redis
- Modify task statuses to disrupt service
- Delete all keys (`FLUSHALL`) to cause data loss
- Use Redis as a pivot for further attacks (e.g., writing SSH keys via `CONFIG SET dir`)

**Recommendation:**
- Remove the `ports` mapping for Redis (it only needs to be accessible within the Docker network)
- Set a Redis password via `--requirepass`
- Consider using Redis ACLs to restrict allowed commands

---

## MEDIUM Findings

### M1. Unbounded Background Task Concurrency

**File:** `app/main.py:96`

```python
background_tasks.add_task(run_splat, task_id, payload)
```

FastAPI's `BackgroundTasks` uses Starlette's default thread pool (typically `anyio`'s default, which often uses 40 threads). There is no application-level limit on concurrent tasks. Every `POST /predict` request adds another task to this pool.

If the pool is saturated, tasks queue up in memory. Each queued task holds a reference to its `CoveragePredictionRequest` object and the task ID. With enough queued tasks, this consumes significant memory even before execution begins.

Additionally, each executing task spawns subprocesses (`srtm2sdf`, `splat`), meaning 40 concurrent tasks could spawn 80+ child processes simultaneously.

**Recommendation:**
- Use a proper task queue (Celery, RQ, or Dramatiq) with bounded worker concurrency
- Alternatively, implement a semaphore to cap concurrent SPLAT! executions
- Return HTTP 429 (Too Many Requests) or HTTP 503 (Service Unavailable) when the queue is full

---

### M2. Content-Disposition Header Injection

**File:** `app/main.py:154`

```python
headers={"Content-Disposition": f"attachment; filename={task_id}.tif"}
```

The `task_id` is generated server-side via `uuid4()` so this is currently safe. However, the `task_id` path parameter from the URL is **not** the value used in the header — the actual task_id comes from the URL path parameter which is an arbitrary string. If an attacker crafts a URL like:

```
GET /result/foo%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

In practice, this would fail because:
1. The task wouldn't exist in Redis (returns 404)
2. Modern HTTP frameworks prevent header injection

However, the `task_id` is used unsanitized in the `Content-Disposition` header value. If a task_id somehow contained special characters (e.g., via a different task creation mechanism in the future), this could become an HTTP response header injection vector.

**Recommendation:**
- Validate `task_id` format (must match `^[0-9a-f-]{36}$`) before using it in any header or Redis query
- Use `Content-Disposition: attachment; filename="result.tif"` with a generic filename

---

### M3. Missing Security Headers

**File:** `app/main.py:35`

The FastAPI application does not set any security headers. The nginx-proxy may add some, but the application itself should set defense-in-depth headers:

Missing headers:
- `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing of the GeoTIFF download
- `X-Frame-Options: DENY` — prevents clickjacking of the SPA
- `Content-Security-Policy` — prevents XSS in the served frontend
- `Strict-Transport-Security` — enforces HTTPS (if TLS is terminated at nginx)
- `Cache-Control` — no caching directives on API responses; proxies may cache sensitive results
- `X-Request-ID` — no request tracing for security incident investigation

**Recommendation:** Add a middleware to set these headers on all responses.

---

### M4. Container Runs as Root

**File:** `Dockerfile:28-53`

The final Docker stage uses `python:3.12-slim` and runs as root (no `USER` directive). This means:
- The Uvicorn process runs as root inside the container
- The SPLAT! subprocesses run as root
- If an attacker achieves code execution via a vulnerability in any dependency (e.g., rasterio, Pillow, or SPLAT! itself processing crafted terrain data), they have root access within the container
- The Docker socket is mounted into the nginx-proxy container (`/var/run/docker.sock:/tmp/docker.sock:ro`), and a root breakout from the app container could pivot to the host

**Recommendation:**
- Add a non-root user to the Dockerfile: `RUN useradd -m appuser && USER appuser`
- Ensure SPLAT! binaries and tile cache are accessible by the non-root user

---

## LOW Findings

### L1. Unused Dependencies Increase Attack Surface

**File:** `requirements.txt`

Several packages are installed but not used in the application code:
- `SQLAlchemy==2.0.36` — no database models or ORM usage
- `celery` dependencies (`amqp`, `billiard`, `kombu`, `vine`) — no Celery task queue configured
- `haversine` — not imported anywhere
- `geojson` — not imported anywhere
- `requests` — not imported (boto3 uses urllib3 directly)
- `scipy` — not imported
- `PyYAML` — not imported directly
- `prompt_toolkit` — not imported

Each unused dependency is additional code that could contain vulnerabilities. `SQLAlchemy` in particular has had SQL injection and denial-of-service CVEs historically.

**Recommendation:** Remove all unused packages from `requirements.txt`.

---

### L2. SPLAT! Binary Output in Logs

**File:** `app/services/splat.py:226-227`

```python
logger.debug(f"SPLAT! stdout:\n{splat_result.stdout}")
logger.debug(f"SPLAT! stderr:\n{splat_result.stderr}")
```

While these are at DEBUG level (and the application runs at INFO), if logging is reconfigured to DEBUG in production, SPLAT! output could leak system information, file paths, and terrain data details into logs. Combined with an exposed log endpoint or log aggregation misconfiguration, this becomes an information disclosure vector.

**Recommendation:** Ensure production logging is set to INFO or higher, and consider sanitizing subprocess output before logging.

---

### L3. HTTP-Only CORS Origin for Production

**File:** `app/main.py:40`

The production CORS origin is `http://site.meshtastic.org` (HTTP, not HTTPS). The docker-compose configuration includes an nginx-proxy with TLS certificate volumes, suggesting the site is intended to be served over HTTPS. If users access via HTTPS, the CORS origin won't match, forcing them to fall back to HTTP — or the API will reject legitimate cross-origin requests.

**Recommendation:** Change to `https://site.meshtastic.org` or include both HTTP and HTTPS origins.

---

## Additional Observations

### Subprocess Injection — NOT Vulnerable

**File:** `app/services/splat.py:218-224`

The SPLAT! subprocess call uses a list-based command (not `shell=True`), which prevents shell injection:

```python
subprocess.run(splat_command, cwd=tmpdir, capture_output=True, text=True, check=False)
```

User-controlled values (`rx_height`, `radius`, `clutter_height`, `signal_threshold`) are passed as list elements via `str()` conversion. This is safe against injection because `subprocess.run` with a list does not invoke a shell.

Similarly, `srtm2sdf` is called with a list-based command and operates on server-generated filenames derived from validated lat/lon coordinates.

### Pydantic Validation — Adequate for Type Safety

**File:** `app/models/CoveragePredictionRequest.py`

The Pydantic model provides good type-level validation with min/max bounds on all numeric fields and `Literal` types for enumerations. The main gap is the server-side radius cap at 500 km (`splat.py:146-148`) which should ideally also be enforced in the Pydantic model (defense in depth).

### Temporary File Handling — Safe

**File:** `app/services/splat.py:138,688`

Both `coverage_prediction` and `_convert_hgt_to_sdf` use `tempfile.TemporaryDirectory()` as a context manager, which ensures cleanup even on exceptions. No temporary files are leaked.

### Redis Key Design — Adequate but Fragile

The Redis key scheme `{task_id}`, `{task_id}:status`, `{task_id}:error` is simple but relies on task_id being a clean UUID. If task_id validation is absent (which it is), an attacker could craft Redis key patterns that collide with other keys or exploit Redis SCAN patterns. The TTL of 3600 seconds (1 hour) prevents indefinite accumulation.

---

## Attack Scenario: Full Exploitation Chain

A motivated attacker targeting this API could:

1. **Reconnaissance:** Send a single `POST /predict` with edge-case values. Read the error response to learn internal paths, binary locations, and infrastructure details.

2. **Resource exhaustion:** Script hundreds of `POST /predict` requests with `radius: 500000` targeting coordinates across different 1-degree tiles (e.g., incrementing lat/lon by 5 degrees each time). Each request forces terrain tile downloads, decompression, conversion, and SPLAT! execution. The server runs out of memory, CPU, and possibly disk space (tile cache is 50 GB).

3. **Data theft:** If other users are using the service concurrently, the attacker can probe `/status/{uuid}` with any task IDs they observe (e.g., from shared URLs or network interception) and download their GeoTIFF results from `/result/{uuid}`.

4. **Redis exploitation:** If the attacker can reach port 6379 (exposed in docker-compose), they can directly read all stored results, flush the database, or use Redis as a pivot.

5. **Persistence:** Since there's no authentication or logging of client identity, the attacker's activity is indistinguishable from legitimate use in the application logs. Only web server access logs (if enabled in nginx-proxy) would capture IP addresses.

---

## Recommended Prioritized Remediation

| Priority | Action | Effort |
|----------|--------|--------|
| 1 | Add rate limiting (e.g., `slowapi` middleware, per-IP) | Low |
| 2 | Remove Redis `ports` mapping from docker-compose | Trivial |
| 3 | Add concurrent task limit (semaphore or queue) | Low |
| 4 | Sanitize error responses (generic messages to client) | Low |
| 5 | Validate `task_id` format as UUID | Trivial |
| 6 | Fix CORS origins to exact values and HTTPS | Trivial |
| 7 | Add security headers middleware | Low |
| 8 | Add authentication mechanism (API keys or tokens) | Medium |
| 9 | Run container as non-root user | Low |
| 10 | Remove unused Python dependencies | Trivial |
