# Proxier

A lightweight Go HTTP service that continuously scans, validates, and serves working free proxies. Designed for IP rotation, scraping pipelines, or any use case that requires fresh, anonymous proxy access.

## Quick Start

### Native

```bash
go build -o proxier ./cmd/proxier/
./proxier
```

The service starts on port 8080 with 14 pre-configured proxy sources. On first run the pool is empty; wait for the first scanner cycle to populate it.

### Docker

```bash
docker compose up -d
```

Or build and run manually:

```bash
docker build -t proxier .
docker run -p 8080:8080 proxier
```

To customize configuration, override the baked-in defaults with environment variables:

```bash
docker run -p 9090:9090 -e PORT=9090 -e SCANNER_INTERVAL_SEC=300 proxier
```

If you need a fully custom config, build your own image with a modified `config.yaml` or mount it into a custom path and set `CONFIG_PATH`.

### Verify

```bash
curl http://localhost:8080/health
# {"status":"ok"}

curl http://localhost:8080/stats | jq
```

## Configuration

All settings live in `config.yaml`. Override any value with environment variables:

| Env Var | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP server port |
| `SCANNER_INTERVAL_SEC` | `600` | Scanner interval in seconds |
| `VALIDATOR_WORKERS` | `20` | Concurrent validation goroutines |
| `VALIDATOR_TIMEOUT_MS` | `5000` | Per-proxy validation timeout |
| `VALIDATOR_PROBE_URL` | `http://httpbin.org/ip` | URL used to test each proxy |
| `KEEPALIVE_INTERVAL_SEC` | `300` | ALIVE proxy re-check interval |
| `MAX_CONSECUTIVE_FAILS` | `3` | Failures before marking DEAD |
| `STORAGE_BACKEND` | `sqlite` | `sqlite` or `json` |
| `STORAGE_PATH` | `./proxies.db` | Database file path |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PROXY_SOURCES` | — | Comma-separated URLs appended to scanner sources |

### Adding Proxy Sources

Add entries under `scanner.sources` in `config.yaml`:

```yaml
scanner:
  sources:
    - url: "https://api.proxyscrape.com/v4/free-proxy-list/get?request=getproxies&protocol=http&limit=2000"
      format: txt
      protocol: http
    - url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"
      format: txt
      protocol: socks5
```

Supported formats: `txt` (ip:port per line) and `json`. Protocols: `http`, `https`, `socks4`, `socks5`, `mixed`.

## API Reference

Base URL: `http://localhost:8080`

### GET /proxy

Returns a single working proxy, selected by weighted random (favors high health score).

**Query Parameters**

| Param | Type | Default | Description |
|---|---|---|---|
| `format` | string | `url` | `url` or `hostport` |
| `protocol` | string | `any` | `http`, `https`, `socks4`, `socks5` |
| `max_latency_ms` | int | none | Only proxies below this latency |

**Response 200**

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

**Response 503**

```json
{ "error": "no proxy available" }
```

### GET /proxies

Returns a list of working proxies.

| Param | Type | Default | Description |
|---|---|---|---|
| `limit` | int | `10` | Max proxies (capped at 100) |
| `format` | string | `url` | Same as `/proxy` |
| `protocol` | string | `any` | Same as `/proxy` |
| `max_latency_ms` | int | none | Same as `/proxy` |
| `sort` | string | `random` | `random`, `latency`, `health_score` |

### GET /rotate

Returns the next proxy using round-robin over the ALIVE pool. Same query parameters as `/proxy`.

### GET /stats

Runtime statistics about the service.

```json
{
  "pool": {
    "alive": 142, "validating": 38, "dead_last_hour": 23,
    "total": 1003, "dead": 417, "discovered": 0,
    "avg_health_score": 0.64,
    "protocols": { "http": 98, "socks5": 44 }
  },
  "scanner": {
    "last_run": "...", "next_run": "...", "sources_count": 14,
    "last_fetch_count": 43200, "total_discovered": 21500,
    "last_duration_ms": 3800
  },
  "validator": {
    "workers": 20, "total_checks": 1580,
    "success_count": 142, "failure_count": 1438,
    "success_rate_pct": 8.9, "avg_latency_ms": 388
  },
  "uptime": "2h3m15s",
  "version": "1.2.0"
}
```

### GET /health

Liveness probe. Returns 200 even if the pool is empty.

```json
{ "status": "ok" }
```

### POST /validate

Manually trigger validation of a specific proxy.

```bash
curl -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{"proxy": "http://123.45.67.89:8080"}'
```

```json
{ "proxy": "http://123.45.67.89:8080", "alive": true, "latency_ms": 290 }
```

## Architecture

```
Scanner (interval) --> Candidate Queue (channel) --> Validator (workers)
                                                         |
                                                    Proxy Pool (in-memory)
                                                         |
                                                    Storage (SQLite)
                                                         |
                                                    HTTP API Server
```

**Scanner** fetches proxy lists from configured sources, deduplicates, and pushes new candidates into a channel. It never validates.

**Validator** runs a configurable pool of workers. Each worker picks a proxy from the channel, routes an HTTP request through it to the probe URL, and measures latency. Successful proxies are promoted to ALIVE with a health score. Failed proxies are demoted after reaching the consecutive failure threshold. A keepalive loop periodically re-checks all ALIVE proxies.

**Proxy Pool** is a thread-safe in-memory store. It supports weighted random selection by health score, round-robin iteration, and protocol/latency filtering. Writes are lock-protected; reads for the HTTP API are served directly.

**Storage** persists proxy state across restarts using SQLite (pure Go, no CGO). An adapter interface allows swapping to other backends.

## Proxy States

```
DISCOVERED --> VALIDATING --> ALIVE
                          --> DEAD (retryable)
```

- **DISCOVERED** — Fetched from a source, not yet tested
- **VALIDATING** — Currently being tested
- **ALIVE** — Confirmed working, available to consumers
- **DEAD** — Failed validation; removed from rotation, may be re-tested on the next scanner cycle

## Health Score

Each ALIVE proxy carries a `health_score` (0.0--1.0) calculated from:

- Response latency (lower is better, 0.4 weight)
- Consecutive successful validations (0.6 weight)

Higher scores are favored during weighted random selection.

## Proxy Sources

The default `config.yaml` ships with 14 sources across these categories:

**Direct APIs** (clean machine-parseable output):
- ProxyScrape v4
- OpenProxyList.xyz

**GitHub Raw Lists** (auto-updated via CI):
- TheSpeedX/PROXY-List
- monosans/proxy-list
- jetkai/proxy-list
- sunny9577/proxy-scraper
- hookzof/socks5_list

All sources are fetched in parallel. Failed sources are logged and skipped; the service continues with whatever is available.

## Project Structure

```
proxier/
  cmd/proxier/main.go          Application entry point
  internal/
    config/                    YAML + env var config loading
    models/                    Shared types (Proxy, Config, API responses)
    pool/                      Thread-safe proxy pool
    scanner/                   Source fetching and parsing
    server/                    HTTP API (6 endpoints)
    storage/                   Persistence layer (SQLite + adapter interface)
    validator/                 Worker pool for proxy health checking
  config.yaml                  Default configuration
  Dockerfile                   Multi-stage Docker build
  docker-compose.yml           Docker Compose orchestration
```

## Non-Goals

- Authentication / API keys — deploy behind a reverse proxy if needed
- Proxy chaining
- Paid proxy support
- Browser fingerprinting
- GUI or dashboard
