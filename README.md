# Proxier

Lightweight Go proxy pool — scan, validate, serve. Built by [tatlilimon](https://github.com/tatlilimon).

Proxier continuously scrapes free proxy lists from 14 sources, validates each proxy in parallel, and exposes a clean REST API for IP rotation. Use it for scraping pipelines, privacy tools, or any workflow that needs fresh anonymous proxies.

```bash
curl http://localhost:8080/proxy?protocol=socks5
# {"proxy":"socks5://1.2.3.4:1080","latency_ms":312,"health_score":0.87}
```

## Quick Start

### Docker (recommended)

```bash
docker compose up -d
curl http://localhost:8080/health      # {"status":"ok"}
curl http://localhost:8080/stats | jq  # pool stats
```

### Native

```bash
go build -o proxier ./cmd/proxier/
./proxier
```

### Customize

Override any config value via environment variables:

```bash
docker run -p 9090:9090 \
  -e PORT=9090 \
  -e VALIDATOR_WORKERS=50 \
  -e SCANNER_INTERVAL_SEC=300 \
  proxier
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP server port |
| `SCANNER_INTERVAL_SEC` | `600` | Source fetch interval |
| `VALIDATOR_WORKERS` | `100` | Concurrent validation workers |
| `VALIDATOR_TIMEOUT_MS` | `3000` | Per-proxy probe timeout |
| `VALIDATOR_PROBE_URL` | `http://httpbin.org/ip` | Endpoint used to test proxies |
| `KEEPALIVE_INTERVAL_SEC` | `120` | ALIVE proxy re-check interval |
| `MAX_CONSECUTIVE_FAILS` | `3` | Failures before marking DEAD |
| `STORAGE_BACKEND` | `sqlite` | `sqlite` or `json` |
| `STORAGE_PATH` | `./proxies.db` | Persistence file path |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PROXY_SOURCES` | — | Comma-separated URLs to append |

### Adding Sources

```yaml
# config.yaml
scanner:
  sources:
    - url: "https://api.proxyscrape.com/v4/free-proxy-list/get?request=getproxies&protocol=http&limit=2000"
      format: txt
      protocol: http
    - url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"
      format: txt
      protocol: socks5
```

Supported formats are `txt` (one `ip:port` per line) and `json`. Supported protocols: `http`, `https`, `socks4`, `socks5`, `mixed`.

## API

Base URL: `http://localhost:8080`

### `GET /proxy`

Returns one working proxy — weighted random selection favoring higher health scores.

| Param | Type | Default | Description |
|---|---|---|---|
| `format` | string | `url` | `url` or `hostport` |
| `protocol` | string | `any` | `http`, `https`, `socks4`, `socks5` |
| `max_latency_ms` | int | — | Max acceptable latency |

```json
{
  "proxy": "http://123.45.67.89:8080",
  "protocol": "http",
  "latency_ms": 312,
  "health_score": 0.87,
  "country": "DE",
  "last_checked": "2026-05-15T14:22:00Z"
}
```

No match returns `503` with `{"error":"no proxy available"}`.

### `GET /proxies`

Returns multiple proxies. Limits are capped at 100.

| Param | Type | Default | Description |
|---|---|---|---|
| `limit` | int | `10` | Max results |
| `sort` | string | `random` | `random`, `latency`, `health_score` |

Supports the same `format`, `protocol`, and `max_latency_ms` filters as `/proxy`.

### `GET /rotate`

Round-robin over the ALIVE pool. Same query params as `/proxy`.

### `GET /stats`

Live runtime statistics.

<details>
<summary>Example response</summary>

```json
{
  "pool": {
    "total": 1003, "alive": 142, "validating": 38,
    "dead": 417, "dead_last_hour": 23,
    "avg_health_score": 0.64,
    "protocols": { "http": 98, "socks5": 44 }
  },
  "scanner": {
    "sources_count": 14, "last_fetch_count": 43200,
    "total_discovered": 21500, "last_duration_ms": 3800,
    "dropped": 0,
    "last_run": "2026-05-24T10:00:00Z", "next_run": "2026-05-24T10:10:00Z"
  },
  "validator": {
    "workers": 100, "total_checks": 1580,
    "success_count": 142, "failure_count": 1438,
    "success_rate_pct": 8.9, "avg_latency_ms": 388
  },
  "uptime": "2h3m15s",
  "version": "1.4.0"
}
```

</details>

### `GET /health`

Liveness probe — returns 200 even with an empty pool.

```json
{ "status": "ok" }
```

### `POST /validate`

Test a specific proxy on demand.

```bash
curl -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{"proxy":"http://123.45.67.89:8080"}'
```

```json
{ "proxy": "http://123.45.67.89:8080", "alive": true, "latency_ms": 290 }
```

### `GET /metrics`

Prometheus exposition format. All pool, scanner, and validator counters as Gauges.

```
# HELP proxier_pool_alive Alive proxies available for rotation
# TYPE proxier_pool_alive gauge
proxier_pool_alive 287
# HELP proxier_validator_success_rate_pct Validation success rate
# TYPE proxier_validator_success_rate_pct gauge
proxier_validator_success_rate_pct 1.97
# HELP proxier_uptime_seconds Process uptime in seconds
# TYPE proxier_uptime_seconds gauge
proxier_uptime_seconds 14378
```

| Metric | Description |
|---|---|
| `proxier_pool_total` | Total proxies tracked |
| `proxier_pool_alive` | Alive proxies available for rotation |
| `proxier_pool_validating` | Proxies currently being validated |
| `proxier_pool_dead` | Dead proxies |
| `proxier_pool_dead_last_hour` | Died within the last hour |
| `proxier_pool_avg_health_score` | Average health score of alive proxies |
| `proxier_pool_protocol_count` | Alive proxies per protocol (labeled: http/socks4/socks5) |
| `proxier_validator_workers` | Concurrent validation workers |
| `proxier_validator_checks_total` | Total validation attempts |
| `proxier_validator_success_total` | Successful validations |
| `proxier_validator_failure_total` | Failed validations |
| `proxier_validator_success_rate_pct` | Validation success rate |
| `proxier_validator_avg_latency_ms` | Average validation latency |
| `proxier_scanner_sources` | Number of active proxy sources |
| `proxier_scanner_last_fetch_count` | Proxies fetched in last cycle |
| `proxier_scanner_discovered_total` | Total unique proxies discovered |
| `proxier_scanner_last_duration_ms` | Last scan cycle duration (ms) |
| `proxier_scanner_dropped_total` | Proxies dropped due to full channel |
| `proxier_uptime_seconds` | Process uptime in seconds |

## Monitoring (Prometheus + Grafana)

`docker compose up -d` starts three services:

| Service | Port | Description |
|---|---|---|
| **proxier** | `:8080` | Proxy pool API + `/metrics` endpoint |
| **prometheus** | `:9090` | Scrapes `/metrics` every 15s, 7-day retention |
| **grafana** | `:3000` | Pre-configured dashboard with 13 panels |

```
http://localhost:3000   →  Grafana (admin / proxier)
http://localhost:9090   →  Prometheus UI
http://localhost:8080   →  Proxier API
```

The Grafana dashboard auto-loads from `grafana/dashboards/proxier.json` and covers pool overview, protocol distribution, validator throughput, success rate, latency, and scanner activity. All panels refresh every 10 seconds.

## Architecture

```
  Sources (14)                Validator Workers (100)
      |                              |
      v                              v
  Scanner ---> Channel (2000) ---> Pool (in-memory)
  (interval)      |                    |
                  | (non-blocking)     v
                  v              Storage (SQLite)
            Dropped counter     (dirty-only persist)
                                      |
                                      v
                              Keepalive Loop
                                      |
                                      v
                              REST API (:8080)
                              /proxy /proxies /rotate
                              /stats /health /validate
                              /metrics (Prometheus)
```

- **Scanner** — Fetches proxy lists, deduplicates, pushes to channel. Non-blocking send — drops when channel is full rather than stalling. Never validates.
- **Validator** — Routes HTTP/SOCKS4/SOCKS5 requests through each proxy to the probe URL. Promotes working proxies to ALIVE with a health score. Demotes failures to DEAD after `MAX_CONSECUTIVE_FAILS`.
- **Keepalive** — Periodically re-checks ALIVE and stuck VALIDATING proxies. Retries recently DEAD proxies.
- **Pool** — Thread-safe in-memory store with atomic counters, weighted random selection, round-robin, and protocol/latency filtering. `DetailedStats()` reads atomics — no full-map lock.
- **Storage** — SQLite persistence (pure Go, modernc.org/sqlite, no CGO). Saves only dirty proxies on each 30s flush cycle.

## Proxy Lifecycle

```
  DISCOVERED ---> VALIDATING ---> ALIVE ----
       (channel)     |                     | (keepalive re-check)
                     v                     v
                   DEAD <--------- VALIDATING
                (retryable)
```

| State | Meaning |
|---|---|
| `DISCOVERED` | Transport-only — scanner to channel to validator. Never visible in `/stats`. |
| `VALIDATING` | Being tested against the probe URL. |
| `ALIVE` | Confirmed working. Available via `/proxy`, `/proxies`, `/rotate`. |
| `DEAD` | Failed `MAX_CONSECUTIVE_FAILS` times. Removed from rotation. May be retried later. |

### Health Score

Each ALIVE proxy carries a score (`0.0`–`1.0`) used for weighted selection:

- Latency — 1.0 at <=100ms, linear ramp to 0 at >=5000ms (x0.4 weight)
- Success streak — `min(consecutive_ok / 10, 1.0)` (x0.6 weight)

## Source List

The default config ships with 14 sources:

| Category | Sources |
|---|---|
| Direct APIs | ProxyScrape v4, OpenProxyList.xyz |
| GitHub Lists | TheSpeedX/PROXY-List, monosans/proxy-list, jetkai/proxy-list, sunny9577/proxy-scraper, hookzof/socks5_list |

All sources are fetched in parallel. Failed sources are skipped — the service continues with whatever is available.

## Non-Goals

- Authentication / API keys (deploy behind a reverse proxy)
- Proxy chaining
- Paid proxy support
- Browser fingerprinting
