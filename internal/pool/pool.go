// Package pool provides a thread-safe, in-memory proxy pool with weighted
// random selection, round-robin iteration, filtered retrieval and check
// scheduling.
//
// Ownership model: the pool owns its records. Every method that returns a
// proxy returns a copy, and every change goes through a pool method that
// holds the write lock and knows the previous state. Callers can therefore
// never change a record behind the pool's back, and the state counters always
// match the records (see Census).
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

// Ack identifies the record versions a storage write covered. Only those
// versions are marked clean, so a change made while the write was running
// stays dirty and is written by the next flush.
type Ack struct {
	versions map[string]uint64
	deleted  map[string]uint64
}

// Pool is a concurrent-safe, in-memory proxy pool.
type Pool struct {
	mu         sync.RWMutex
	proxies    map[string]*models.Proxy
	aliveIDs   []string       // IDs of ALIVE records, for selection
	alivePos   map[string]int // ID -> index in aliveIDs
	tombstones map[string]uint64
	version    uint64
	rrIdx      atomic.Uint64

	// Counters are written under the write lock and read without it.
	totalVal      atomic.Int64
	aliveVal      atomic.Int64
	validatingVal atomic.Int64
	deadVal       atomic.Int64
	discoveredVal atomic.Int64

	protoCount     map[string]int64 // ALIVE records per protocol; under mu
	deadTimestamps []time.Time      // deaths in the last hour; under mu
}

// NewPool returns an initialized Pool.
func NewPool() *Pool {
	return &Pool{
		proxies:    make(map[string]*models.Proxy),
		alivePos:   make(map[string]int),
		tombstones: make(map[string]uint64),
		protoCount: make(map[string]int64),
	}
}

// Add stores a copy of proxy, inserting or replacing the record. A DISCOVERED
// record never overwrites an existing record's validation history: it is
// treated as a rediscovery (see Merge).
func (p *Pool) Add(proxy *models.Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	rec := *proxy
	prev, exists := p.proxies[rec.ID]
	if exists && rec.State == models.StateDiscovered && prev.State != models.StateDiscovered {
		p.rediscoverLocked(prev, rec, time.Now())
		return
	}
	p.putLocked(&rec, prev, exists, time.Now())
}

// Merge adds scanner candidates. Unknown candidates become DISCOVERED records
// that are due for their first check immediately; known records keep their
// history, and a DEAD record becomes due for a recheck because a source lists
// it again. It returns the number of new records.
func (p *Pool) Merge(candidates []models.Proxy) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	added := 0
	for _, c := range candidates {
		if c.ID == "" {
			c.ID = models.ProxyID(c.Protocol, c.Host, c.Port)
		}
		if prev, ok := p.proxies[c.ID]; ok {
			p.rediscoverLocked(prev, c, now)
			continue
		}
		rec := c
		rec.State = models.StateDiscovered
		rec.NextCheck = time.Time{}
		if rec.FirstSeen.IsZero() {
			rec.FirstSeen = now.UTC()
		}
		p.putLocked(&rec, nil, false, now)
		added++
	}
	return added
}

// rediscoverLocked applies a source listing an existing record again.
func (p *Pool) rediscoverLocked(rec *models.Proxy, cand models.Proxy, now time.Time) {
	changed := false
	if rec.Source == "" && cand.Source != "" {
		rec.Source = cand.Source
		changed = true
	}
	if rec.State == models.StateDead && (rec.NextCheck.IsZero() || rec.NextCheck.After(now)) {
		rec.NextCheck = now
		changed = true
	}
	if changed {
		p.version++
		rec.Version = p.version
		rec.Dirty = true
	}
}

// Update applies fn to the stored record under the write lock and keeps the
// counters, the rotation index and the persistence state consistent with the
// result. fn must not call other Pool methods. The ID and protocol are
// identity and cannot be changed. It returns false if the record is unknown.
func (p *Pool) Update(id string, fn func(rec *models.Proxy)) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	rec, ok := p.proxies[id]
	if !ok {
		return false
	}
	prevState, prevProto := rec.State, rec.Protocol
	fn(rec)
	rec.ID, rec.Protocol = id, prevProto
	p.version++
	rec.Version = p.version
	rec.Dirty = true
	p.transitionLocked(id, prevState, true, rec.State, rec.Protocol, time.Now())
	return true
}

// Remove deletes a proxy from the pool by ID. The deletion is reported to
// storage by the next DirtySnapshot.
func (p *Pool) Remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(id)
}

func (p *Pool) removeLocked(id string) bool {
	rec, ok := p.proxies[id]
	if !ok {
		return false
	}
	delete(p.proxies, id)
	p.totalVal.Add(-1)
	if c := p.stateCounter(rec.State); c != nil {
		c.Add(-1)
	}
	if rec.State == models.StateAlive {
		p.protoDecLocked(rec.Protocol)
		p.removeAliveLocked(id)
	}
	p.version++
	p.tombstones[id] = p.version
	return true
}

// Get returns a copy of the proxy with the given ID, if present.
func (p *Pool) Get(id string) (*models.Proxy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	rec, ok := p.proxies[id]
	if !ok {
		return nil, false
	}
	cp := *rec
	return &cp, true
}

// GetRandom returns a copy of a random ALIVE proxy using weighted selection
// based on health_score. Returns ErrPoolEmpty when no matching proxies exist.
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
		return copyOf(candidates[idx]), nil
	}

	threshold, err := cryptoRandFloat64(totalWeight)
	if err != nil {
		return nil, err
	}

	cumulative := 0.0
	for _, proxy := range candidates {
		cumulative += proxy.HealthScore
		if cumulative >= threshold {
			return copyOf(proxy), nil
		}
	}

	return copyOf(candidates[len(candidates)-1]), nil
}

// GetRoundRobin returns a copy of the next ALIVE proxy in round-robin order.
func (p *Pool) GetRoundRobin(filter PoolFilter) (*models.Proxy, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	candidates := p.filterAlive(filter)
	if len(candidates) == 0 {
		return nil, ErrPoolEmpty
	}

	idx := p.rrIdx.Add(1) - 1
	return copyOf(candidates[idx%uint64(len(candidates))]), nil
}

// GetN returns copies of up to N ALIVE proxies sorted by the given criteria.
// sort values: "random", "latency", "health_score". Defaults to "random".
func (p *Pool) GetN(limit int, sortBy string, filter PoolFilter) []*models.Proxy {
	p.mu.RLock()
	candidates := p.filterAlive(filter)
	result := make([]*models.Proxy, len(candidates))
	for i, c := range candidates {
		result[i] = copyOf(c)
	}
	p.mu.RUnlock()

	if len(result) == 0 {
		return nil
	}

	switch sortBy {
	case "latency":
		sort.SliceStable(result, func(i, j int) bool {
			return result[i].LatencyMs < result[j].LatencyMs
		})
	case "health_score":
		sort.SliceStable(result, func(i, j int) bool {
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

// Size returns the number of ALIVE proxies in the pool.
func (p *Pool) Size() int {
	return int(p.aliveVal.Load())
}

// Len returns the number of records of any state.
func (p *Pool) Len() int {
	return int(p.totalVal.Load())
}

// All returns a copy of every record currently in the pool.
func (p *Pool) All() []*models.Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*models.Proxy, 0, len(p.proxies))
	for _, rec := range p.proxies {
		result = append(result, copyOf(rec))
	}
	return result
}

// Due returns copies of up to limit records whose next check is due at now,
// most important first: ALIVE rechecks, then records that worked before,
// then new candidates, then never-working retries, then DEAD retries. Within
// a group the longest-waiting record comes first. skip, when non-nil,
// excludes records (for example checks already in flight); it is called
// under the pool's read lock and must not call back into the pool.
func (p *Pool) Due(now time.Time, limit int, skip func(id string) bool) []*models.Proxy {
	if limit <= 0 {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	due := make([]*models.Proxy, 0, 64)
	for id, rec := range p.proxies {
		if !isDue(rec, now) {
			continue
		}
		if skip != nil && skip(id) {
			continue
		}
		due = append(due, rec)
	}
	sort.Slice(due, func(i, j int) bool {
		ri, rj := priority(due[i]), priority(due[j])
		if ri != rj {
			return ri < rj
		}
		if !due[i].NextCheck.Equal(due[j].NextCheck) {
			return due[i].NextCheck.Before(due[j].NextCheck)
		}
		return due[i].ID < due[j].ID
	})
	if len(due) > limit {
		due = due[:limit]
	}
	out := make([]*models.Proxy, len(due))
	for i, rec := range due {
		out[i] = copyOf(rec)
	}
	return out
}

func isDue(rec *models.Proxy, now time.Time) bool {
	if rec.State == models.StateDead {
		return !rec.NextCheck.IsZero() && !rec.NextCheck.After(now)
	}
	return !rec.NextCheck.After(now)
}

func priority(rec *models.Proxy) int {
	switch rec.State {
	case models.StateAlive:
		return 0
	case models.StateValidating:
		if !rec.LastSuccess.IsZero() {
			return 1
		}
		return 3
	case models.StateDiscovered:
		return 2
	default:
		return 4
	}
}

// DirtySnapshot returns copies of every changed record and the IDs of
// removed records that storage has not yet acknowledged. Nothing is marked
// clean here: pass the Ack to Acknowledge after the write succeeds.
func (p *Pool) DirtySnapshot() (upserts []*models.Proxy, deletes []string, ack Ack) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ack = Ack{versions: make(map[string]uint64), deleted: make(map[string]uint64)}
	for id, rec := range p.proxies {
		if rec.Dirty {
			cp := *rec
			cp.Dirty = false
			upserts = append(upserts, &cp)
			ack.versions[id] = rec.Version
		}
	}
	for id, v := range p.tombstones {
		deletes = append(deletes, id)
		ack.deleted[id] = v
	}
	return upserts, deletes, ack
}

// Acknowledge marks the versions covered by a successful write as clean.
// Records changed after the snapshot keep their dirty flag.
func (p *Pool) Acknowledge(ack Ack) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, v := range ack.versions {
		if rec, ok := p.proxies[id]; ok && rec.Version == v {
			rec.Dirty = false
		}
	}
	for id, v := range ack.deleted {
		if tv, ok := p.tombstones[id]; ok && tv == v {
			delete(p.tombstones, id)
		}
	}
}

// Pending returns the number of changes not yet acknowledged by storage.
func (p *Pool) Pending() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.tombstones)
	for _, rec := range p.proxies {
		if rec.Dirty {
			n++
		}
	}
	return n
}

// Load replaces the pool's contents with records read from storage, building
// the indexes and counters once. A persisted ALIVE record whose last success
// is older than freshFor is quarantined: it becomes VALIDATING and due now,
// so it is not served until a check confirms it again. It returns the number
// of quarantined records.
func (p *Pool) Load(records []*models.Proxy, now time.Time, freshFor time.Duration) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.proxies = make(map[string]*models.Proxy, len(records))
	p.tombstones = make(map[string]uint64)
	quarantined := 0
	for _, r := range records {
		rec := *r
		rec.Dirty = false
		if rec.State == models.StateAlive && rec.LastSuccess.IsZero() {
			// Stored before last_success existed: an ALIVE record last
			// succeeded at its last check.
			rec.LastSuccess = rec.LastChecked
		}
		if rec.State == models.StateAlive && now.Sub(lastGood(&rec)) > freshFor {
			rec.State = models.StateValidating
			rec.NextCheck = time.Time{}
			rec.Dirty = true
			quarantined++
		}
		p.version++
		rec.Version = p.version
		p.proxies[rec.ID] = &rec
	}
	p.recountLocked(now)
	return quarantined
}

// SeedCounters recalculates every counter and index from the records.
func (p *Pool) SeedCounters() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recountLocked(time.Now())
}

func (p *Pool) recountLocked(now time.Time) {
	var total, alive, validating, dead, discovered int64
	p.protoCount = make(map[string]int64)
	p.aliveIDs = p.aliveIDs[:0]
	p.alivePos = make(map[string]int)
	p.deadTimestamps = p.deadTimestamps[:0]
	cutoff := now.Add(-time.Hour)

	for id, rec := range p.proxies {
		total++
		switch rec.State {
		case models.StateAlive:
			alive++
			p.protoCount[string(rec.Protocol)]++
			p.alivePos[id] = len(p.aliveIDs)
			p.aliveIDs = append(p.aliveIDs, id)
		case models.StateValidating:
			validating++
		case models.StateDead:
			dead++
			if rec.DiedAt.After(cutoff) {
				p.deadTimestamps = append(p.deadTimestamps, rec.DiedAt)
			}
		case models.StateDiscovered:
			discovered++
		}
	}
	p.totalVal.Store(total)
	p.aliveVal.Store(alive)
	p.validatingVal.Store(validating)
	p.deadVal.Store(dead)
	p.discoveredVal.Store(discovered)
}

// Prune removes DEAD records that died (or were last checked) before
// now-retention. It returns the number of removed records.
func (p *Pool) Prune(now time.Time, retention time.Duration) int {
	if retention <= 0 {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	cutoff := now.Add(-retention)
	removed := 0
	for id, rec := range p.proxies {
		if rec.State != models.StateDead {
			continue
		}
		since := rec.DiedAt
		if since.IsZero() {
			since = rec.LastChecked
		}
		if since.Before(cutoff) && p.removeLocked(id) {
			removed++
		}
	}
	return removed
}

// DemoteStale takes ALIVE records out of rotation when their last success is
// older than staleAfter (for example because rechecks fell behind). They
// become VALIDATING and due now. It returns the number of demoted records.
func (p *Pool) DemoteStale(now time.Time, staleAfter time.Duration) int {
	if staleAfter <= 0 {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	demoted := 0
	for _, id := range append([]string(nil), p.aliveIDs...) {
		rec := p.proxies[id]
		if now.Sub(lastGood(rec)) <= staleAfter {
			continue
		}
		rec.State = models.StateValidating
		rec.NextCheck = time.Time{}
		p.version++
		rec.Version = p.version
		rec.Dirty = true
		p.transitionLocked(id, models.StateAlive, true, models.StateValidating, rec.Protocol, now)
		demoted++
	}
	return demoted
}

// Census counts records by state by inspecting every record. It is the
// reference the cheap counters must always agree with.
func (p *Pool) Census() map[models.ProxyState]int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[models.ProxyState]int)
	for _, rec := range p.proxies {
		out[rec.State]++
	}
	return out
}

// DetailedStats returns pool statistics. State counts come from counters
// that are maintained on every transition.
func (p *Pool) DetailedStats() models.PoolStats {
	stats := models.PoolStats{
		Total:      int(p.totalVal.Load()),
		Alive:      int(p.aliveVal.Load()),
		Validating: int(p.validatingVal.Load()),
		Dead:       int(p.deadVal.Load()),
		Discovered: int(p.discoveredVal.Load()),
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	stats.Protocols = make(map[string]int, len(p.protoCount))
	for proto, cnt := range p.protoCount {
		stats.Protocols[proto] = int(cnt)
	}

	cutoff := time.Now().Add(-time.Hour)
	for _, ts := range p.deadTimestamps {
		if ts.After(cutoff) {
			stats.DeadLastHour++
		}
	}

	if n := len(p.aliveIDs); n > 0 {
		var healthSum float64
		for _, id := range p.aliveIDs {
			healthSum += p.proxies[id].HealthScore
		}
		stats.AvgHealthScore = healthSum / float64(n)
	}
	return stats
}

// putLocked stores rec (owned by the pool from now on).
func (p *Pool) putLocked(rec, prev *models.Proxy, exists bool, now time.Time) {
	prevState := models.ProxyState("")
	if exists {
		prevState = prev.State
		if prev.State == models.StateAlive && prev.Protocol != rec.Protocol {
			// Same ID with a different protocol cannot happen through
			// ProxyID; keep the protocol counts right regardless.
			p.protoDecLocked(prev.Protocol)
			p.protoCount[string(rec.Protocol)]++
		}
	} else {
		p.totalVal.Add(1)
	}
	p.version++
	rec.Version = p.version
	rec.Dirty = true
	p.proxies[rec.ID] = rec
	delete(p.tombstones, rec.ID)
	p.transitionLocked(rec.ID, prevState, exists, rec.State, rec.Protocol, now)
}

// transitionLocked updates the counters and the rotation index for a state
// change of one record.
func (p *Pool) transitionLocked(id string, from models.ProxyState, existed bool, to models.ProxyState, proto models.Protocol, now time.Time) {
	if existed && from == to {
		return
	}
	if existed {
		if c := p.stateCounter(from); c != nil {
			c.Add(-1)
		}
	}
	if c := p.stateCounter(to); c != nil {
		c.Add(1)
	}

	wasAlive := existed && from == models.StateAlive
	isAlive := to == models.StateAlive
	switch {
	case wasAlive && !isAlive:
		p.protoDecLocked(proto)
		p.removeAliveLocked(id)
	case !wasAlive && isAlive:
		p.protoCount[string(proto)]++
		p.alivePos[id] = len(p.aliveIDs)
		p.aliveIDs = append(p.aliveIDs, id)
	}

	if to == models.StateDead && (!existed || from != models.StateDead) {
		cutoff := now.Add(-time.Hour)
		kept := p.deadTimestamps[:0]
		for _, ts := range p.deadTimestamps {
			if ts.After(cutoff) {
				kept = append(kept, ts)
			}
		}
		p.deadTimestamps = append(kept, now)
	}
}

func (p *Pool) protoDecLocked(proto models.Protocol) {
	p.protoCount[string(proto)]--
	if p.protoCount[string(proto)] <= 0 {
		delete(p.protoCount, string(proto))
	}
}

func (p *Pool) removeAliveLocked(id string) {
	pos, ok := p.alivePos[id]
	if !ok {
		return
	}
	last := len(p.aliveIDs) - 1
	p.aliveIDs[pos] = p.aliveIDs[last]
	p.alivePos[p.aliveIDs[pos]] = pos
	p.aliveIDs = p.aliveIDs[:last]
	delete(p.alivePos, id)
}

func (p *Pool) stateCounter(state models.ProxyState) *atomic.Int64 {
	switch state {
	case models.StateAlive:
		return &p.aliveVal
	case models.StateValidating:
		return &p.validatingVal
	case models.StateDead:
		return &p.deadVal
	case models.StateDiscovered:
		return &p.discoveredVal
	}
	return nil
}

// filterAlive must be called under the read lock. It re-checks the state of
// every indexed record as a defence in depth.
func (p *Pool) filterAlive(filter PoolFilter) []*models.Proxy {
	result := make([]*models.Proxy, 0, len(p.aliveIDs))
	for _, id := range p.aliveIDs {
		rec, ok := p.proxies[id]
		if !ok || rec.State != models.StateAlive {
			continue
		}
		if filter.matches(rec) {
			result = append(result, rec)
		}
	}
	return result
}

// lastGood is the time of the last successful check, falling back to the
// last check for records stored before LastSuccess existed.
func lastGood(rec *models.Proxy) time.Time {
	if !rec.LastSuccess.IsZero() {
		return rec.LastSuccess
	}
	return rec.LastChecked
}

func copyOf(rec *models.Proxy) *models.Proxy {
	cp := *rec
	return &cp
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
