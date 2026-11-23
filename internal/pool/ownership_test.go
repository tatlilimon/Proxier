package pool

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
)

func rec(id string, state models.ProxyState) *models.Proxy {
	return &models.Proxy{ID: id, Host: "198.51.100.1", Port: 80, Protocol: models.ProtoHTTP, State: state}
}

func assertCensus(t *testing.T, p *Pool) {
	t.Helper()
	s, c := p.DetailedStats(), p.Census()
	total := 0
	for _, n := range c {
		total += n
	}
	if s.Alive != c[models.StateAlive] || s.Validating != c[models.StateValidating] || s.Dead != c[models.StateDead] ||
		s.Discovered != c[models.StateDiscovered] || s.Total != total || p.Size() != c[models.StateAlive] {
		t.Fatalf("counters %+v (size %d) disagree with census %v", s, p.Size(), c)
	}
	sum := 0
	for _, n := range s.Protocols {
		sum += n
	}
	if sum != s.Alive {
		t.Fatalf("protocol counts %v do not sum to alive %d", s.Protocols, s.Alive)
	}
}

// Audit finding 1: callers get copies and cannot change pool state behind
// its back.
func TestReturnedProxiesAreCopies(t *testing.T) {
	p := NewPool()
	p.Add(rec("a", models.StateAlive))

	got, _ := p.Get("a")
	got.State = models.StateDead
	for _, x := range p.All() {
		x.State = models.StateDead
	}
	sel, _ := p.GetRandom(PoolFilter{})
	sel.State = models.StateDead

	again, _ := p.Get("a")
	if again.State != models.StateAlive || p.Size() != 1 {
		t.Fatalf("mutating returned copies changed the pool: %+v size %d", again, p.Size())
	}
	assertCensus(t, p)
}

func TestUpdateKeepsCountersEqualToCensus(t *testing.T) {
	p := NewPool()
	states := []models.ProxyState{models.StateDiscovered, models.StateValidating, models.StateAlive, models.StateDead}
	protos := []models.Protocol{models.ProtoHTTP, models.ProtoSOCKS4, models.ProtoSOCKS5}
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 50; i++ {
		x := rec(fmt.Sprint(i), states[r.IntN(len(states))])
		x.Protocol = protos[r.IntN(len(protos))]
		p.Add(x)
	}
	for i := 0; i < 2000; i++ {
		id := fmt.Sprint(r.IntN(60))
		switch r.IntN(10) {
		case 0:
			p.Remove(id)
		case 1:
			p.Merge([]models.Proxy{*rec(id, models.StateDiscovered)})
		default:
			to := states[r.IntN(len(states))]
			p.Update(id, func(x *models.Proxy) { x.State = to; x.ID = "tampered"; x.Protocol = models.ProtoHTTPS })
		}
	}
	assertCensus(t, p)
	for _, x := range p.All() {
		if x.ID == "tampered" || x.Protocol == models.ProtoHTTPS {
			t.Fatalf("Update changed identity: %+v", x)
		}
		if x.State == models.StateAlive {
			if _, ok := p.alivePos[x.ID]; !ok {
				t.Fatalf("alive record %s missing from the rotation index", x.ID)
			}
		}
	}
	if len(p.aliveIDs) != p.Size() {
		t.Fatalf("rotation index has %d entries, %d alive", len(p.aliveIDs), p.Size())
	}
}

// Audit finding 5: a failed write keeps records dirty, and a change made
// during a write survives its acknowledgement.
func TestDirtySnapshotAcknowledge(t *testing.T) {
	p := NewPool()
	p.Add(rec("a", models.StateAlive))
	p.Add(rec("b", models.StateValidating))

	up, _, _ := p.DirtySnapshot()
	if len(up) != 2 {
		t.Fatalf("snapshot has %d records, want 2", len(up))
	}
	// Write failed: no Acknowledge. Everything is still pending.
	if up2, _, _ := p.DirtySnapshot(); len(up2) != 2 || p.Pending() != 2 {
		t.Fatalf("after a failed write: snapshot %d pending %d, want 2 and 2", len(up2), p.Pending())
	}

	_, _, ack := p.DirtySnapshot()
	p.Update("a", func(x *models.Proxy) { x.LatencyMs = 42 }) // concurrent change
	p.Acknowledge(ack)
	up3, _, _ := p.DirtySnapshot()
	if len(up3) != 1 || up3[0].ID != "a" || up3[0].LatencyMs != 42 {
		t.Fatalf("after ack: snapshot %+v, want only the newer change of a", up3)
	}

	p.Remove("b")
	_, del, ack := p.DirtySnapshot()
	if len(del) != 1 || del[0] != "b" {
		t.Fatalf("deletes = %v, want [b]", del)
	}
	p.Acknowledge(ack)
	if p.Pending() != 0 {
		t.Fatalf("pending = %d after acknowledging everything", p.Pending())
	}
}

func TestMergeAddsCandidatesAndRediscoversDead(t *testing.T) {
	p := NewPool()
	now := time.Now()
	dead := rec("d", models.StateDead)
	dead.ConsecutiveFail = 9
	dead.NextCheck = time.Time{} // no retries left
	p.Add(dead)

	added := p.Merge([]models.Proxy{
		{ID: "n", Host: "198.51.100.2", Port: 80, Protocol: models.ProtoHTTP},
		{ID: "d", Host: "198.51.100.1", Port: 80, Protocol: models.ProtoHTTP, State: models.StateDiscovered},
	})
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}
	d, _ := p.Get("d")
	if d.State != models.StateDead || d.ConsecutiveFail != 9 || d.NextCheck.IsZero() || d.NextCheck.After(time.Now()) {
		t.Fatalf("rediscovered dead record = %+v, want history kept and due now", d)
	}
	n, _ := p.Get("n")
	if n.State != models.StateDiscovered || n.FirstSeen.Before(now.Add(-time.Second)) {
		t.Fatalf("new candidate = %+v", n)
	}
	assertCensus(t, p)
}

func TestDueOrderAndSkip(t *testing.T) {
	p := NewPool()
	now := time.Now()
	add := func(id string, state models.ProxyState, next time.Time, lastSuccess time.Time) {
		x := rec(id, state)
		x.NextCheck = next
		x.LastSuccess = lastSuccess
		p.Add(x)
	}
	add("dead-due", models.StateDead, now.Add(-time.Minute), time.Time{})
	add("dead-never", models.StateDead, time.Time{}, time.Time{})
	add("new", models.StateDiscovered, time.Time{}, time.Time{})
	add("retry-junk", models.StateValidating, now.Add(-time.Second), time.Time{})
	add("retry-good", models.StateValidating, now.Add(-time.Second), now.Add(-time.Hour))
	add("alive-later", models.StateAlive, now.Add(time.Hour), now)
	add("alive-old", models.StateAlive, now.Add(-2*time.Minute), now)
	add("alive-new", models.StateAlive, now.Add(-time.Minute), now)

	var order []string
	for _, x := range p.Due(now, 100, nil) {
		order = append(order, x.ID)
	}
	want := []string{"alive-old", "alive-new", "retry-good", "new", "retry-junk", "dead-due"}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("due order = %v, want %v", order, want)
	}
	skipped := p.Due(now, 2, func(id string) bool { return id == "alive-old" })
	if len(skipped) != 2 || skipped[0].ID != "alive-new" || skipped[1].ID != "retry-good" {
		t.Fatalf("skip/limit: %v", skipped)
	}
}

// Audit finding 9: persisted ALIVE records are quarantined until rechecked
// unless they were confirmed recently.
func TestLoadQuarantinesStaleAlive(t *testing.T) {
	now := time.Now()
	fresh := rec("fresh", models.StateAlive)
	fresh.LastSuccess = now.Add(-30 * time.Second)
	stale := rec("stale", models.StateAlive)
	stale.LastChecked = now.Add(-24 * time.Hour)
	recentDead := rec("dead", models.StateDead)
	recentDead.DiedAt = now.Add(-10 * time.Minute)

	p := NewPool()
	q := p.Load([]*models.Proxy{fresh, stale, recentDead}, now, 2*time.Minute)
	if q != 1 {
		t.Fatalf("quarantined = %d, want 1", q)
	}
	if s, _ := p.Get("stale"); s.State != models.StateValidating || !s.Dirty {
		t.Fatalf("stale record = %+v, want VALIDATING and dirty", s)
	}
	if sel, err := p.GetRandom(PoolFilter{}); err != nil || sel.ID != "fresh" {
		t.Fatalf("selection = %v, %v; want only the fresh record", sel, err)
	}
	if st := p.DetailedStats(); st.DeadLastHour != 1 {
		t.Errorf("dead_last_hour = %d, want 1 (from died_at)", st.DeadLastHour)
	}
	assertCensus(t, p)
}

func TestPruneAndDemoteStale(t *testing.T) {
	now := time.Now()
	p := NewPool()
	old := rec("old-dead", models.StateDead)
	old.DiedAt = now.Add(-48 * time.Hour)
	young := rec("young-dead", models.StateDead)
	young.DiedAt = now.Add(-time.Hour)
	aliveStale := rec("stale", models.StateAlive)
	aliveStale.LastSuccess = now.Add(-time.Hour)
	aliveFresh := rec("fresh", models.StateAlive)
	aliveFresh.LastSuccess = now
	for _, x := range []*models.Proxy{old, young, aliveStale, aliveFresh} {
		p.Add(x)
	}

	if n := p.Prune(now, 24*time.Hour); n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	if _, ok := p.Get("old-dead"); ok {
		t.Fatal("old dead record still present")
	}
	if n := p.DemoteStale(now, 10*time.Minute); n != 1 {
		t.Fatalf("demoted %d, want 1", n)
	}
	if s, _ := p.Get("stale"); s.State != models.StateValidating {
		t.Fatalf("stale record state = %s", s.State)
	}
	_, del, _ := p.DirtySnapshot()
	if len(del) != 1 || del[0] != "old-dead" {
		t.Fatalf("pruned record not reported for deletion: %v", del)
	}
	assertCensus(t, p)
}

func TestFilterAliveRechecksState(t *testing.T) {
	p := NewPool()
	p.Add(rec("a", models.StateAlive))
	// Corrupt the index on purpose: selection must still refuse the record.
	p.proxies["a"].State = models.StateDead
	if _, err := p.GetRandom(PoolFilter{}); err == nil {
		t.Fatal("selected a record whose state is not ALIVE")
	}
}

func TestConcurrentPoolAccess(t *testing.T) {
	p := NewPool()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(w), 9))
			for i := 0; i < 2000; i++ {
				id := fmt.Sprint(r.IntN(100))
				switch r.IntN(6) {
				case 0:
					p.Merge([]models.Proxy{*rec(id, models.StateDiscovered)})
				case 1:
					p.Update(id, func(x *models.Proxy) { x.State = models.StateAlive; x.HealthScore = r.Float64() })
				case 2:
					p.Update(id, func(x *models.Proxy) { x.State = models.StateDead })
				case 3:
					p.GetN(10, "health_score", PoolFilter{})
					p.GetRandom(PoolFilter{})
					p.GetRoundRobin(PoolFilter{})
				case 4:
					if _, _, ack := p.DirtySnapshot(); r.IntN(2) == 0 {
						p.Acknowledge(ack)
					}
				default:
					p.DetailedStats()
					p.Due(time.Now(), 10, nil)
				}
			}
		})
	}
	wg.Wait()
	assertCensus(t, p)
}
