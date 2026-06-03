// Package pool provides a thread-safe, in-memory proxy pool with weighted
// random selection, round-robin iteration, and filtered retrieval.
package pool

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
)

// ErrPoolEmpty is returned when the pool has no proxies matching the filter.
var ErrPoolEmpty = errors.New("proxy pool is empty or no proxies match the filter")

// PoolFilter constrains proxy selection by protocol and maximum latency.
type PoolFilter struct {
	Protocol     string // "" or "any" matches all protocols
	MaxLatencyMs int    // 0 means no filtering
}

func (f PoolFilter) matches(p *models.Proxy) bool {
	if f.Protocol != "" && f.Protocol != "any" && string(p.Protocol) != f.Protocol {
		return false
	}
	if f.MaxLatencyMs > 0 && p.LatencyMs > f.MaxLatencyMs {
		return false
	}
	return true
}

// Pool is a concurrent-safe, in-memory proxy pool.
type Pool struct {
	mu       sync.RWMutex
	proxies  map[string]*models.Proxy
	aliveIDs []string
	rrIdx    atomic.Uint64

	// Atomic counters updated in Add/Remove so DetailedStats avoids a full
	// proxy iteration.
	totalVal      atomic.Int64
	aliveVal      atomic.Int64
	validatingVal atomic.Int64
	deadVal       atomic.Int64

	// Protocol counts per alive proxy, protected by protoMu to avoid
	// contention with the main pool lock.
	protoMu    sync.Mutex
	protoCount map[string]int64

	// Recent dead timestamps for dead_last_hour calculation.
	deadTimesMu    sync.Mutex
	deadTimestamps []time.Time
}

// NewPool returns an initialized Pool.
func NewPool() *Pool {
	return &Pool{
		proxies:    make(map[string]*models.Proxy),
		protoCount: make(map[string]int64),
	}
}

// Add inserts or updates a proxy in the pool and adjusts the atomic counters
// based on state transitions. Re-discovered proxies with accumulated
// validation state are preserved.
func (p *Pool) Add(proxy *models.Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	prev, exists := p.proxies[proxy.ID]

	if exists && proxy.State == models.StateDiscovered && prev.State != models.StateDiscovered {
		proxy.ConsecutiveFail = prev.ConsecutiveFail
		proxy.ConsecutiveOK = prev.ConsecutiveOK
		proxy.HealthScore = prev.HealthScore
		proxy.State = prev.State
		proxy.LastChecked = prev.LastChecked
		proxy.FirstSeen = prev.FirstSeen
	}

	if !exists {
		p.totalVal.Add(1)
	}

	prevState := models.StateDiscovered
	if exists {
		prevState = prev.State
	}
	newState := proxy.State

	proxy.Dirty = true
	p.proxies[proxy.ID] = proxy

	p.adjustCounters(prevState, newState, proxy.Protocol, proxy.HealthScore)

	wasAlive := prevState == models.StateAlive
	isAlive := newState == models.StateAlive
	if wasAlive != isAlive || !exists {
		p.rebuildAliveIDs()
	}
}

// Remove deletes a proxy from the pool by ID and updates the counters.
func (p *Pool) Remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy, exists := p.proxies[id]
	if !exists {
		return
	}
	delete(p.proxies, id)

	p.totalVal.Add(-1)
	p.adjustCounters(proxy.State, models.StateDiscovered, proxy.Protocol, proxy.HealthScore)

	if proxy.State == models.StateAlive {
		p.rebuildAliveIDs()
	}
}

// Get returns the proxy with the given ID, if present.
func (p *Pool) Get(id string) (*models.Proxy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	proxy, ok := p.proxies[id]
	return proxy, ok
}

// GetRandom returns a random alive proxy using weighted selection based on
// health_score. Returns ErrPoolEmpty when no matching proxies exist.
func (p *Pool) GetRandom(filter PoolFilter) (*models.Proxy, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	candidates := p.filterAlive(filter)
	if len(candidates) == 0 {
		return nil, ErrPoolEmpty
	}

	totalWeight := 0.0
	for _, proxy := range candidates {
		totalWeight += proxy.HealthScore
	}

	if totalWeight <= 0 {
		idx, err := cryptoRandInt(len(candidates))
		if err != nil {
			return nil, err
		}
		return candidates[idx], nil
	}

	threshold, err := cryptoRandFloat64(totalWeight)
	if err != nil {
		return nil, err
	}

	cumulative := 0.0
	for _, proxy := range candidates {
		cumulative += proxy.HealthScore
		if cumulative >= threshold {
			return proxy, nil
		}
	}

	return candidates[len(candidates)-1], nil
}

// GetRoundRobin returns the next alive proxy using round-robin iteration.
func (p *Pool) GetRoundRobin(filter PoolFilter) (*models.Proxy, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	candidates := p.filterAlive(filter)
	if len(candidates) == 0 {
		return nil, ErrPoolEmpty
	}

	idx := p.rrIdx.Add(1) - 1
	return candidates[idx%uint64(len(candidates))], nil
}

// GetN returns up to N proxies sorted by the given criteria.
// sort values: "random", "latency", "health_score". Defaults to "random".
func (p *Pool) GetN(limit int, sortBy string, filter PoolFilter) []*models.Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	candidates := p.filterAlive(filter)
	if len(candidates) == 0 {
		return nil
	}

	result := make([]*models.Proxy, len(candidates))
	copy(result, candidates)

	switch sortBy {
	case "latency":
		sort.Slice(result, func(i, j int) bool {
			return result[i].LatencyMs < result[j].LatencyMs
		})
	case "health_score":
		sort.Slice(result, func(i, j int) bool {
			return result[i].HealthScore > result[j].HealthScore
		})
	default:
		shuffleSlice(result)
	}

	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}

	return result
}

// Size returns the number of alive proxies in the pool.
func (p *Pool) Size() int {
	return int(p.aliveVal.Load())
}

// All returns a copy of every proxy currently in the pool.
func (p *Pool) All() []*models.Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*models.Proxy, 0, len(p.proxies))
	for _, proxy := range p.proxies {
		result = append(result, proxy)
	}
	return result
}

// DirtyAll returns copies of every proxy that has been modified since the
// last persistence flush, then clears the dirty flag.
func (p *Pool) DirtyAll() []*models.Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*models.Proxy, 0, len(p.proxies)/4)
	for _, proxy := range p.proxies {
		if proxy.Dirty {
			cp := *proxy
			cp.Dirty = false
			result = append(result, &cp)
			proxy.Dirty = false
		}
	}
	return result
}

// SeedCounters recalibrates all atomic state counters to match the actual
// proxy states in the pool. Call after bulk-loading proxies from storage so
// counters start from a known-correct baseline when the pool is populated.
func (p *Pool) SeedCounters() {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var total, alive, validating, dead int64
	protoCounts := make(map[string]int64)

	for _, proxy := range p.proxies {
		total++
		switch proxy.State {
		case models.StateAlive:
			alive++
			protoCounts[string(proxy.Protocol)]++
		case models.StateValidating:
			validating++
		case models.StateDead:
			dead++
		}
	}

	p.totalVal.Store(total)
	p.aliveVal.Store(alive)
	p.validatingVal.Store(validating)
	p.deadVal.Store(dead)

	p.protoMu.Lock()
	p.protoCount = protoCounts
	p.protoMu.Unlock()
}

// DetailedStats returns comprehensive pool statistics. Counts come from
// atomic counters (no proxy iteration). Protocol counts and health score
// averages use lightweight, dedicated locks.
func (p *Pool) DetailedStats() models.PoolStats {
	stats := models.PoolStats{
		Total:      int(p.totalVal.Load()),
		Alive:      int(p.aliveVal.Load()),
		Validating: int(p.validatingVal.Load()),
		Dead:       int(p.deadVal.Load()),
	}

	// Protocol counts from the lightweight protoMu.
	p.protoMu.Lock()
	stats.Protocols = make(map[string]int, len(p.protoCount))
	for proto, cnt := range p.protoCount {
		stats.Protocols[proto] = int(cnt)
	}
	p.protoMu.Unlock()

	// Dead-last-hour from the timestamp ring.
	p.deadTimesMu.Lock()
	cutoff := time.Now().Add(-1 * time.Hour)
	for _, ts := range p.deadTimestamps {
		if ts.After(cutoff) {
			stats.DeadLastHour++
		}
	}
	p.deadTimesMu.Unlock()

	// Avg health score: only iterate alive proxies, not the full map.
	if stats.Alive > 0 {
		p.mu.RLock()
		var healthSum float64
		for _, id := range p.aliveIDs {
			if proxy, ok := p.proxies[id]; ok {
				healthSum += proxy.HealthScore
			}
		}
		p.mu.RUnlock()
		stats.AvgHealthScore = healthSum / float64(stats.Alive)
	}

	return stats
}

// adjustCounters applies atomic counter and protocol-count changes for a
// state transition. Must be called under the pool write lock.
func (p *Pool) adjustCounters(from, to models.ProxyState, protocol models.Protocol, healthScore float64) {
	p.updateStateCounter(from, -1)
	p.updateStateCounter(to, +1)

	if from == models.StateAlive {
		p.protoMu.Lock()
		p.protoCount[string(protocol)]--
		if p.protoCount[string(protocol)] <= 0 {
			delete(p.protoCount, string(protocol))
		}
		p.protoMu.Unlock()
	}

	if to == models.StateAlive {
		p.protoMu.Lock()
		p.protoCount[string(protocol)]++
		p.protoMu.Unlock()
	}

	if to == models.StateDead && from != models.StateDead {
		p.deadTimesMu.Lock()
		p.deadTimestamps = append(p.deadTimestamps, time.Now())
		// Prune timestamps older than 1 hour.
		cutoff := time.Now().Add(-1 * time.Hour)
		kept := p.deadTimestamps[:0]
		for _, ts := range p.deadTimestamps {
			if ts.After(cutoff) {
				kept = append(kept, ts)
			}
		}
		p.deadTimestamps = kept
		p.deadTimesMu.Unlock()
	}
}

func (p *Pool) updateStateCounter(state models.ProxyState, delta int64) {
	switch state {
	case models.StateAlive:
		p.aliveVal.Add(delta)
	case models.StateValidating:
		p.validatingVal.Add(delta)
	case models.StateDead:
		p.deadVal.Add(delta)
	}
}

// Must be called under write lock.
func (p *Pool) rebuildAliveIDs() {
	ids := make([]string, 0, len(p.proxies))
	for _, proxy := range p.proxies {
		if proxy.State == models.StateAlive {
			ids = append(ids, proxy.ID)
		}
	}
	p.aliveIDs = ids
}

// Must be called under read lock.
func (p *Pool) filterAlive(filter PoolFilter) []*models.Proxy {
	result := make([]*models.Proxy, 0, len(p.aliveIDs))
	for _, id := range p.aliveIDs {
		proxy, ok := p.proxies[id]
		if !ok {
			continue
		}
		if filter.matches(proxy) {
			result = append(result, proxy)
		}
	}
	return result
}

func cryptoRandInt(n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(n)), nil
}

func cryptoRandFloat64(max float64) (float64, error) {
	if max <= 0 {
		return 0, nil
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	frac := float64(binary.BigEndian.Uint64(buf[:])&((1<<53)-1)) / float64(1<<53)
	return frac * max, nil
}

func shuffleSlice(proxies []*models.Proxy) {
	var buf [8]byte
	n := len(proxies)
	for i := n - 1; i > 0; i-- {
		if _, err := rand.Read(buf[:]); err != nil {
			return
		}
		j := int(binary.BigEndian.Uint64(buf[:]) % uint64(i+1))
		proxies[i], proxies[j] = proxies[j], proxies[i]
	}
}
