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
}

// NewPool returns an initialized Pool.
func NewPool() *Pool {
	return &Pool{
		proxies: make(map[string]*models.Proxy),
	}
}

func (p *Pool) Add(proxy *models.Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	prev, exists := p.proxies[proxy.ID]
	if exists && proxy.State == models.StateDiscovered && prev.State != models.StateDiscovered {
		// Scanner re-discovered a proxy that already has validation state.
		// Preserve accumulated history — don't let scanner overwrite it.
		proxy.ConsecutiveFail = prev.ConsecutiveFail
		proxy.ConsecutiveOK = prev.ConsecutiveOK
		proxy.HealthScore = prev.HealthScore
		proxy.State = prev.State
		proxy.LastChecked = prev.LastChecked
		proxy.FirstSeen = prev.FirstSeen // keep original discovery time
	}
	p.proxies[proxy.ID] = proxy

	// Rebuild the alive slice only when the alive set changes.
	wasAlive := exists && prev.State == models.StateAlive
	isAlive := proxy.State == models.StateAlive

	if wasAlive != isAlive || !exists {
		p.rebuildAliveIDs()
	}
}

func (p *Pool) Remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy, exists := p.proxies[id]
	if !exists {
		return
	}
	delete(p.proxies, id)
	if proxy.State == models.StateAlive {
		p.rebuildAliveIDs()
	}
}

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

	// Fallback to uniform random when totalWeight is 0 (or negative).
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

	// Safety fallback (should not normally be reached).
	return candidates[len(candidates)-1], nil
}

// GetRoundRobin returns the next alive proxy using round-robin iteration.
// The counter is maintained atomically across calls.
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
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.aliveIDs)
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

// Stats returns proxy counts grouped by state.
func (p *Pool) Stats() (alive int, validating int, dead int) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, proxy := range p.proxies {
		switch proxy.State {
		case models.StateAlive:
			alive++
		case models.StateValidating:
			validating++
		case models.StateDead:
			dead++
		}
	}
	return
}

// DetailedStats returns comprehensive pool statistics in a single lock
// acquisition.
func (p *Pool) DetailedStats() models.PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	var stats models.PoolStats
	stats.Protocols = make(map[string]int)

	var healthSum float64
	aliveCount := 0

	for _, proxy := range p.proxies {
		stats.Total++
		switch proxy.State {
		case models.StateAlive:
			stats.Alive++
			aliveCount++
			healthSum += proxy.HealthScore
			stats.Protocols[string(proxy.Protocol)]++
		case models.StateValidating:
			stats.Validating++
		case models.StateDead:
			stats.Dead++
			if proxy.LastChecked.After(cutoff) {
				stats.DeadLastHour++
			}
		}
	}

	if aliveCount > 0 {
		stats.AvgHealthScore = healthSum / float64(aliveCount)
	}

	return stats
}

// LastHourDead returns the count of proxies that transitioned to DEAD
// within the last hour.
func (p *Pool) LastHourDead() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	count := 0
	for _, proxy := range p.proxies {
		if proxy.State == models.StateDead && proxy.LastChecked.After(cutoff) {
			count++
		}
	}
	return count
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
	// Use 53 bits of mantissa precision for float64.
	frac := float64(binary.BigEndian.Uint64(buf[:])&((1<<53)-1)) / float64(1<<53)
	return frac * max, nil
}

func shuffleSlice(proxies []*models.Proxy) {
	var buf [8]byte
	n := len(proxies)
	for i := n - 1; i > 0; i-- {
		if _, err := rand.Read(buf[:]); err != nil {
			// On error, skip shuffling and return the original order.
			return
		}
		j := int(binary.BigEndian.Uint64(buf[:]) % uint64(i+1))
		proxies[i], proxies[j] = proxies[j], proxies[i]
	}
}
