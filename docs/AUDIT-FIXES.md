# September 2026 audit: fixes and tests

The code and runtime audit of 7 September 2026 (`audit/2026-09-07/REPORT.md`, kept outside the repository with its raw evidence) listed 19 finding groups, missing capabilities and dependency results. This page maps each to its fix and to the tests that cover it. Where the audit had a reproduction (`audit/2026-09-07/repro`), it was ported as a regression test; the other tests were written for the fixes.

All tests run offline against local fixtures (`internal/fakeproxy`): `go test -race ./...`.

| # | Finding | Fix | Tests |
|---|---|---|---|
| 1 | P1 — Shared mutable proxies break state tracking and concurrency safety | The pool owns its records: getters return copies, all changes go through `Update`/`Merge`/`Load` under the write lock with the previous state known; the rotation index is maintained per transition; selection re-checks the state | `pool.TestReturnedProxiesAreCopies`, `TestUpdateKeepsCountersEqualToCensus`, `TestConcurrentPoolAccess`, `TestFilterAliveRechecksState`; `validator.TestDeadProxyIsNotSelectableAndCountersAgree`, `TestConcurrentValidationKeepsCountersConsistent` |
| 2 | P1 — Background validation disables TLS authentication | Certificates and host names are verified everywhere (probe, HTTPS proxies, baseline); extra roots only via `extra_ca_file` | `validator.TestCheckRejectsUntrustedTLS` (untrusted HTTPS proxy and TLS-intercepting proxy) |
| 3 | P1 — Invalid or leaking probe responses accepted | The answer must be a bounded JSON document whose origins are valid IPs, none of them the client's own; the baseline is retried with backoff and refreshed; unknown baseline = indeterminate | `validator.TestCheckRejectsInvalidAndLeakingAnswers`, `TestCheckWithUnknownBaselineIsIndeterminate`, `TestParseOrigins` |
| 4 | P1 — SOCKS5 connection establishment ignores cancellation | Context-aware SOCKS5 dialer over a bounded `net.Dialer`; SOCKS4 handshake honours deadline and cancellation and dials the real target | `validator.TestSOCKS5DialHonoursCancellation`; `socks4.TestDialContextHonoursDeadlineWhenProxyStalls`, `TestDialContextHonoursCancellation` |
| 5 | P1 — Failed persistence silently omitted from the next retry | Dirty flags are cleared per record version only after a successful commit; failures are counted and exported | `pool.TestDirtySnapshotAcknowledge`; `main.TestPersisterRetriesFailedWrites` |
| 6 | P2 — Docker's keepalive configuration duplicates work | One scheduler; each due record is marked in flight and sent to exactly one queue | `validator.TestScheduleSendsEachRecordToExactlyOneQueue` |
| 7 | P2 — `/validate` implements a different, incomplete validator | `/validate` uses the same side-effect-free `Checker` (all protocols, TLS, redirects, routing) and reports a reason | `server.TestValidateMatchesBackgroundValidation`, `TestValidateSpeaksSOCKS4OnTheWire` |
| 8 | P2 — Rediscovery resets accumulated history | Candidates are merged into the canonical record; results are applied to it | `validator.TestRediscoveryKeepsHistory`; `pool.TestMergeAddsCandidatesAndRediscoversDead` |
| 9 | P2 — Retried records stuck for hours; startup serves stale state | Explicit `next_check` with backoff and priority order; `died_at` and `last_success` stored; stale persisted ALIVE records quarantined at startup; ALIVE records unconfirmed for three intervals demoted | `pool.TestDueOrderAndSkip`, `TestLoadQuarantinesStaleAlive`, `TestPruneAndDemoteStale`; `validator.TestFailureBackoffAndDeadRetries`, `TestScheduleRechecksAliveBeforeBacklog`; `main.TestEndToEnd` (freshness) |
| 10 | P2 — Deduplication loses protocol alternatives and suppresses dropped candidates | Identity includes the protocol; candidates are stored in the pool (never dropped) and marked seen only afterwards; `mixed` and scheme-prefixed lines are defined and parsed | `scanner.TestDeduplicateKeepsProtocolAlternatives`, `TestCycleNeverSuppressesUnstoredCandidates`, `TestParseTXTMixedSource`, `TestParseTXTSchemeOverridesSourceProtocol` |
| 11 | P2 — Monitoring exports invalid metadata and a fabricated histogram | Official Prometheus client, one definition per family, real latency histogram, lint-clean names | `metrics.TestMetricsPassLint`, `TestLatencyHistogramIsRealAndCumulative` |
| 12 | P2 — Latency and health scores misrepresent quality | Average latency covers successful checks only; every failure resets the success streak | `validator.TestSuccessStreakResetsOnFailure` |
| 13 | P2 — Configuration not validated before starting workers | The merged configuration is validated once; malformed environment values are errors; `log_level` from YAML is honoured | `config.TestValidateRejectsInvalidValues`, `TestMalformedEnvironmentIsAnError`, `TestLoadUsesYAMLLogLevelAndReportsBadFiles`, `TestShippedConfigIsValid` |
| 14 | P2 — API listener failure does not fail the process | The listener is bound before workers start; any API failure shuts down and exits nonzero | `main.TestRunFailsWhenThePortIsTaken` |
| 15 | P2 — Input/network boundaries and request budgets incomplete | Strict proxy parsing; address policy for private destinations (also after DNS resolution); server timeouts; 4 KiB body limit; 8 concurrent validations | `netpolicy` tests; `server.TestParseProxyStringRejectsInvalidInput`, `TestValidateRefusesLoopbackByDefault`, `TestValidateRequestBounds`; `scanner.TestParseRefusesPrivateAddressesUnlessAllowed`; `validator.TestCheckRefusesPrivateAddressesByDefault` |
| 16 | P2 — Shutdown does not join background work before final persistence | Stop the API, cancel and join workers, scanner and persistence loop, then write the final state; cancellable timers; cancelled checks change nothing | `main.TestEndToEnd` (two clean shutdowns and a restart); `validator.TestCanceledCheckChangesNothing`; `scanner.TestRunContinuousSchedulesAfterCompletionAndStops` |
| 17 | P2 — No retention or bounded growth policy | DEAD records pruned after `dead_retention_hours`; incremental index and bulk load; SQLite WAL, busy timeout, single connection, schema version, integrity check | `pool.TestPruneAndDemoteStale`, `TestLoadQuarantinesStaleAlive`; `storage.TestMigrateLegacyDatabase`, `TestRefusesNewerSchema`, `TestCorruptFileIsRefusedAndLeftAlone` |
| 18 | P3 — IPv6 inconsistently accepted and formatted | `net.JoinHostPort` everywhere; IPv6 lines parse; normalized identity | `server.TestParseProxyStringIPv6`; `scanner.TestParseTXT` ("ipv6 bracket notation"); `storage.TestApplyRoundTripAndDelete` |
| 19 | P3 — Misleading scanner status fields and dashboard labels | Parallel fetching in both modes; consistent `last_fetch_count`, `last_new_count`, `total_discovered` and `next_run`; per-source status; dashboard units and thresholds fixed | `scanner.TestFetchAllSourcesIsParallelAndReportsSources`, `TestCycleNeverSuppressesUnstoredCandidates`, `TestRunContinuousSchedulesAfterCompletionAndStops`; `metrics.TestDashboardQueriesExistingMetrics` |

## Missing capabilities

| Item | Outcome |
|---|---|
| JSON storage advertised but not implemented | Removed from the supported options; `json` is rejected at startup (`storage.TestNewRejectsUnsupportedBackend`, `config.TestValidateRejectsInvalidValues`). The unused Redis setting was removed. |
| No readiness endpoint | `GET /ready` (`server.TestHealthReadyAndStats`) |
| Missing per-source, queue, active-check, failure-reason and persistence metrics | Added to `/metrics` and `/stats` |
| Country and anonymity not populated | Documented as not populated; the README no longer shows an example country or claims anonymity classification |
| Grafana without a persistent volume, floating image tags, known admin password, no resource/log limits | `grafana_data` volume, pinned `prom/prometheus:v3.13.2` and `grafana/grafana:13.1.3`, password required from `.env`, memory limits and log rotation |
| Container runs as root | **Not changed.** The existing `proxier_data` volume holds a root-owned database; switching to a non-root user needs an ownership migration that could not be tested here without building and running the image. |
| Tests do not cover validation, storage, server, SOCKS, lifecycle or metrics; no CI | Covered by the tests above; `.github/workflows/ci.yml` runs gofmt, vet, race tests, build and govulncheck |
| README defaults diverge from code, YAML and Compose | The README documents the three layers side by side |

## Dependencies

- `golang.org/x/net` is now v0.60.0. The audit flagged GO-2026-5026 in v0.54.0; a later advisory affects v0.57.0 and is fixed in v0.60.0, which requires Go 1.26.
- The module now requires **Go 1.26**. The Go 1.25 line has reachable standard-library vulnerabilities (`net/http`, `net/textproto`, `crypto/tls`, `crypto/x509`, including GO-2026-6603 to GO-2026-6859) that are fixed only in Go 1.26.9–1.26.11. CI uses the latest 1.26 patch release and the Docker image uses `golang:1.26-alpine`.
- `github.com/prometheus/client_golang` v1.24.1 was added.
- `govulncheck` v1.3.0 with Go 1.26.11 is part of CI.
