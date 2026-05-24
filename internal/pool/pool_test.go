package pool

import (
	"testing"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
)

func TestAdd(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-1 * time.Hour)

	tests := []struct {
		name              string
		first             *models.Proxy // nil means skip first add
		second            *models.Proxy
		wantState         models.ProxyState
		wantConsecutiveOK int
		wantConsecutiveFail int
		wantHealthScore   float64
		wantFirstSeen     time.Time
		wantLastChecked   time.Time
		wantAliveIDsLen   int
	}{
		{
			name:            "new proxy added to pool",
			second:          &models.Proxy{ID: "abc", Host: "1.2.3.4", Port: 8080, Protocol: models.ProtoHTTP, State: models.StateDiscovered},
			wantState:       models.StateDiscovered,
			wantAliveIDsLen: 0,
		},
		{
			name: "rediscovery preserves validation state",
			first: &models.Proxy{
				ID: "xyz", Host: "5.6.7.8", Port: 3128, Protocol: models.ProtoHTTP,
				State: models.StateAlive, ConsecutiveOK: 7, ConsecutiveFail: 0,
				HealthScore: 0.82, FirstSeen: earlier, LastChecked: now,
			},
			second: &models.Proxy{
				ID: "xyz", Host: "5.6.7.8", Port: 3128, Protocol: models.ProtoHTTP,
				State: models.StateDiscovered, FirstSeen: now,
			},
			wantState:         models.StateAlive,
			wantConsecutiveOK: 7,
			wantConsecutiveFail: 0,
			wantHealthScore:   0.82,
			wantFirstSeen:     earlier, // original discovery time preserved
			wantLastChecked:   now,
			wantAliveIDsLen:   1,
		},
		{
			name: "alive overwrites discovered",
			first: &models.Proxy{
				ID: "def", Host: "10.0.0.1", Port: 1080, Protocol: models.ProtoSOCKS5,
				State: models.StateDiscovered, ConsecutiveOK: 0, ConsecutiveFail: 0,
				HealthScore: 0, FirstSeen: earlier,
			},
			second: &models.Proxy{
				ID: "def", Host: "10.0.0.1", Port: 1080, Protocol: models.ProtoSOCKS5,
				State: models.StateAlive, ConsecutiveOK: 3, ConsecutiveFail: 0,
				HealthScore: 0.65, FirstSeen: now, LastChecked: now,
			},
			wantState:         models.StateAlive,
			wantConsecutiveOK: 3,
			wantHealthScore:   0.65,
			wantFirstSeen:     now, // overwritten because new is not Discovered
			wantLastChecked:   now,
			wantAliveIDsLen:   1,
		},
		{
			name: "dead overwrites discovered",
			first: &models.Proxy{
				ID: "ghi", Host: "10.0.0.2", Port: 1080, Protocol: models.ProtoSOCKS5,
				State: models.StateDiscovered, ConsecutiveOK: 0, ConsecutiveFail: 0,
				HealthScore: 0,
			},
			second: &models.Proxy{
				ID: "ghi", Host: "10.0.0.2", Port: 1080, Protocol: models.ProtoSOCKS5,
				State: models.StateDead, ConsecutiveOK: 0, ConsecutiveFail: 5,
				HealthScore: 0, LastChecked: now,
			},
			wantState:         models.StateDead,
			wantConsecutiveFail: 5,
			wantHealthScore:   0,
			wantLastChecked:   now,
			wantAliveIDsLen:   0,
		},
		{
			name: "discovered after discovered gets overwritten",
			first: &models.Proxy{
				ID: "jkl", Host: "1.1.1.1", Port: 80, Protocol: models.ProtoHTTP,
				State: models.StateDiscovered, ConsecutiveOK: 0, ConsecutiveFail: 0,
				HealthScore: 0, FirstSeen: earlier,
			},
			second: &models.Proxy{
				ID: "jkl", Host: "1.1.1.1", Port: 80, Protocol: models.ProtoHTTP,
				State: models.StateDiscovered, FirstSeen: now,
			},
			wantState:       models.StateDiscovered,
			wantFirstSeen:   now, // overwritten (both discovered)
			wantAliveIDsLen: 0,
		},
		{
			name: "adding alive rebuilds aliveIDs",
			first: &models.Proxy{
				ID: "mno", Host: "2.2.2.2", Port: 8080, Protocol: models.ProtoHTTP,
				State: models.StateDiscovered,
			},
			second: &models.Proxy{
				ID: "mno", Host: "2.2.2.2", Port: 8080, Protocol: models.ProtoHTTP,
				State: models.StateAlive, ConsecutiveOK: 2, HealthScore: 0.5,
			},
			wantState:         models.StateAlive,
			wantConsecutiveOK: 2,
			wantHealthScore:   0.5,
			wantAliveIDsLen:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPool()
			if tt.first != nil {
				p.Add(tt.first)
			}
			p.Add(tt.second)

			got, ok := p.Get(tt.second.ID)
			if !ok {
				t.Fatal("proxy not found in pool after Add")
			}

			if got.State != tt.wantState {
				t.Errorf("State = %q, want %q", got.State, tt.wantState)
			}
			if got.ConsecutiveOK != tt.wantConsecutiveOK {
				t.Errorf("ConsecutiveOK = %d, want %d", got.ConsecutiveOK, tt.wantConsecutiveOK)
			}
			if got.ConsecutiveFail != tt.wantConsecutiveFail {
				t.Errorf("ConsecutiveFail = %d, want %d", got.ConsecutiveFail, tt.wantConsecutiveFail)
			}
			if got.HealthScore != tt.wantHealthScore {
				t.Errorf("HealthScore = %f, want %f", got.HealthScore, tt.wantHealthScore)
			}

			// FirstSeen and LastChecked are only checked when specified.
			if !tt.wantFirstSeen.IsZero() && !got.FirstSeen.Equal(tt.wantFirstSeen) {
				t.Errorf("FirstSeen = %v, want %v", got.FirstSeen, tt.wantFirstSeen)
			}
			if !tt.wantLastChecked.IsZero() && !got.LastChecked.Equal(tt.wantLastChecked) {
				t.Errorf("LastChecked = %v, want %v", got.LastChecked, tt.wantLastChecked)
			}

			if len(p.aliveIDs) != tt.wantAliveIDsLen {
				t.Errorf("aliveIDs len = %d, want %d", len(p.aliveIDs), tt.wantAliveIDsLen)
			}
		})
	}
}

func TestGetRandom(t *testing.T) {
	t.Run("empty pool returns error", func(t *testing.T) {
		p := NewPool()
		_, err := p.GetRandom(PoolFilter{})
		if err != ErrPoolEmpty {
			t.Errorf("expected ErrPoolEmpty, got %v", err)
		}
	})

	t.Run("single alive proxy returns it", func(t *testing.T) {
		p := NewPool()
		proxy := &models.Proxy{
			ID: "a", Host: "1.2.3.4", Port: 8080, Protocol: models.ProtoHTTP,
			State: models.StateAlive, HealthScore: 0.8,
		}
		p.Add(proxy)

		got, err := p.GetRandom(PoolFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "a" {
			t.Errorf("got ID %q, want %q", got.ID, "a")
		}
	})

	t.Run("returns alive proxy from multiple candidates", func(t *testing.T) {
		p := NewPool()
		// Only alive proxies are candidates. Dead/validating are ignored.
		p.Add(&models.Proxy{ID: "a", State: models.StateAlive, HealthScore: 0.9, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "b", State: models.StateAlive, HealthScore: 0.6, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "c", State: models.StateDead, HealthScore: 0, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "d", State: models.StateValidating, HealthScore: 0, Protocol: models.ProtoHTTP})

		got, err := p.GetRandom(PoolFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should return either a or b.
		if got.ID != "a" && got.ID != "b" {
			t.Errorf("got ID %q, expected 'a' or 'b' (alive only)", got.ID)
		}
	})

	t.Run("protocol filter excludes non-matching", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "h1", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "s1", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoSOCKS5})

		got, err := p.GetRandom(PoolFilter{Protocol: "socks5"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "s1" {
			t.Errorf("got ID %q, want 's1'", got.ID)
		}
	})

	t.Run("latency filter excludes high-latency", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "fast", State: models.StateAlive, HealthScore: 0.9, LatencyMs: 50, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "slow", State: models.StateAlive, HealthScore: 0.3, LatencyMs: 2000, Protocol: models.ProtoHTTP})

		got, err := p.GetRandom(PoolFilter{MaxLatencyMs: 100})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "fast" {
			t.Errorf("got ID %q, want 'fast'", got.ID)
		}
	})

	t.Run("filter leaves no candidates", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "h1", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})

		_, err := p.GetRandom(PoolFilter{Protocol: "socks5"})
		if err != ErrPoolEmpty {
			t.Errorf("expected ErrPoolEmpty, got %v", err)
		}
	})

	t.Run("zero health scores fallback to uniform random", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "z1", State: models.StateAlive, HealthScore: 0, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "z2", State: models.StateAlive, HealthScore: 0, Protocol: models.ProtoHTTP})

		got, err := p.GetRandom(PoolFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "z1" && got.ID != "z2" {
			t.Errorf("got ID %q, expected 'z1' or 'z2'", got.ID)
		}
	})
}

func TestGetRoundRobin(t *testing.T) {
	t.Run("empty pool returns error", func(t *testing.T) {
		p := NewPool()
		_, err := p.GetRoundRobin(PoolFilter{})
		if err != ErrPoolEmpty {
			t.Errorf("expected ErrPoolEmpty, got %v", err)
		}
	})

	t.Run("single proxy returned each time", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "only", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})

		for i := 0; i < 5; i++ {
			got, err := p.GetRoundRobin(PoolFilter{})
			if err != nil {
				t.Fatalf("call %d: unexpected error: %v", i, err)
			}
			if got.ID != "only" {
				t.Errorf("call %d: got ID %q, want 'only'", i, got.ID)
			}
		}
	})

	t.Run("cycles through alive proxies", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "a", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "b", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "dead", State: models.StateDead, Protocol: models.ProtoHTTP})

		seen := map[string]int{}
		for i := 0; i < 20; i++ {
			got, err := p.GetRoundRobin(PoolFilter{})
			if err != nil {
				t.Fatalf("call %d: unexpected error: %v", i, err)
			}
			seen[got.ID]++
		}
		// Both alive proxies should be returned.
		if seen["a"] == 0 {
			t.Error("proxy 'a' was never returned")
		}
		if seen["b"] == 0 {
			t.Error("proxy 'b' was never returned")
		}
		// Dead proxy should never be returned.
		if seen["dead"] > 0 {
			t.Error("dead proxy was returned")
		}
	})

	t.Run("filter applies to round-robin", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "h1", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "s1", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoSOCKS5})

		got, err := p.GetRoundRobin(PoolFilter{Protocol: "socks5"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "s1" {
			t.Errorf("got ID %q, want 's1'", got.ID)
		}
	})
}

func TestGetN(t *testing.T) {
	t.Run("empty pool returns nil", func(t *testing.T) {
		p := NewPool()
		result := p.GetN(10, "random", PoolFilter{})
		if result != nil {
			t.Errorf("expected nil, got %d proxies", len(result))
		}
	})

	t.Run("sort by latency ascending", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "a", State: models.StateAlive, LatencyMs: 300, HealthScore: 0.5, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "b", State: models.StateAlive, LatencyMs: 100, HealthScore: 0.9, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "c", State: models.StateAlive, LatencyMs: 200, HealthScore: 0.7, Protocol: models.ProtoHTTP})

		result := p.GetN(0, "latency", PoolFilter{})
		if len(result) != 3 {
			t.Fatalf("got %d proxies, want 3", len(result))
		}
		if result[0].ID != "b" || result[1].ID != "c" || result[2].ID != "a" {
			t.Errorf("got order [%s, %s, %s], want [b, c, a]", result[0].ID, result[1].ID, result[2].ID)
		}
	})

	t.Run("sort by health_score descending", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "a", State: models.StateAlive, LatencyMs: 300, HealthScore: 0.5, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "b", State: models.StateAlive, LatencyMs: 100, HealthScore: 0.9, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "c", State: models.StateAlive, LatencyMs: 200, HealthScore: 0.7, Protocol: models.ProtoHTTP})

		result := p.GetN(0, "health_score", PoolFilter{})
		if len(result) != 3 {
			t.Fatalf("got %d proxies, want 3", len(result))
		}
		if result[0].ID != "b" || result[1].ID != "c" || result[2].ID != "a" {
			t.Errorf("got order [%s, %s, %s], want [b, c, a]", result[0].ID, result[1].ID, result[2].ID)
		}
	})

	t.Run("default sort random returns all", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "a", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "b", State: models.StateAlive, HealthScore: 0.9, Protocol: models.ProtoHTTP})

		result := p.GetN(0, "", PoolFilter{})
		if len(result) != 2 {
			t.Errorf("got %d proxies, want 2", len(result))
		}
	})

	t.Run("limit truncates results", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "a", State: models.StateAlive, LatencyMs: 300, HealthScore: 0.5, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "b", State: models.StateAlive, LatencyMs: 100, HealthScore: 0.9, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "c", State: models.StateAlive, LatencyMs: 200, HealthScore: 0.7, Protocol: models.ProtoHTTP})

		result := p.GetN(2, "latency", PoolFilter{})
		if len(result) != 2 {
			t.Fatalf("got %d proxies, want 2", len(result))
		}
		if result[0].ID != "b" || result[1].ID != "c" {
			t.Errorf("got [%s, %s], want [b, c]", result[0].ID, result[1].ID)
		}
	})

	t.Run("limit larger than pool returns all", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "a", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})

		result := p.GetN(100, "latency", PoolFilter{})
		if len(result) != 1 {
			t.Errorf("got %d proxies, want 1", len(result))
		}
	})

	t.Run("protocol filter applied", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "h1", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})
		p.Add(&models.Proxy{ID: "s1", State: models.StateAlive, HealthScore: 0.9, Protocol: models.ProtoSOCKS5})

		result := p.GetN(10, "health_score", PoolFilter{Protocol: "socks5"})
		if len(result) != 1 {
			t.Fatalf("got %d proxies, want 1", len(result))
		}
		if result[0].ID != "s1" {
			t.Errorf("got ID %q, want 's1'", result[0].ID)
		}
	})

	t.Run("filter leaves no candidates returns nil", func(t *testing.T) {
		p := NewPool()
		p.Add(&models.Proxy{ID: "h1", State: models.StateAlive, HealthScore: 0.5, Protocol: models.ProtoHTTP})

		result := p.GetN(10, "random", PoolFilter{Protocol: "socks5"})
		if result != nil {
			t.Errorf("expected nil, got %d proxies", len(result))
		}
	})
}

func TestStats(t *testing.T) {
	tests := []struct {
		name         string
		proxies      []*models.Proxy
		wantAlive    int
		wantValidating int
		wantDead     int
	}{
		{
			name:      "empty pool",
			proxies:   nil,
			wantAlive: 0, wantValidating: 0, wantDead: 0,
		},
		{
			name: "only alive",
			proxies: []*models.Proxy{
				{ID: "a", State: models.StateAlive},
				{ID: "b", State: models.StateAlive},
			},
			wantAlive: 2, wantValidating: 0, wantDead: 0,
		},
		{
			name: "mixed states",
			proxies: []*models.Proxy{
				{ID: "a", State: models.StateAlive},
				{ID: "b", State: models.StateAlive},
				{ID: "c", State: models.StateValidating},
				{ID: "d", State: models.StateDead},
				{ID: "e", State: models.StateDead},
				{ID: "f", State: models.StateDead},
			},
			wantAlive: 2, wantValidating: 1, wantDead: 3,
		},
		{
			name: "discovered not counted",
			proxies: []*models.Proxy{
				{ID: "a", State: models.StateDiscovered},
				{ID: "b", State: models.StateAlive},
			},
			wantAlive: 1, wantValidating: 0, wantDead: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPool()
			for _, proxy := range tt.proxies {
				p.Add(proxy)
			}
			stats := p.DetailedStats()
			alive, validating, dead := stats.Alive, stats.Validating, stats.Dead
			if alive != tt.wantAlive {
				t.Errorf("alive = %d, want %d", alive, tt.wantAlive)
			}
			if validating != tt.wantValidating {
				t.Errorf("validating = %d, want %d", validating, tt.wantValidating)
			}
			if dead != tt.wantDead {
				t.Errorf("dead = %d, want %d", dead, tt.wantDead)
			}
		})
	}
}

func TestDetailedStats(t *testing.T) {
	now := time.Now()
	recentlyDead := now.Add(-30 * time.Minute)
	oldDead := now.Add(-2 * time.Hour)

	p := NewPool()
	p.Add(&models.Proxy{ID: "a1", State: models.StateAlive, HealthScore: 0.9, Protocol: models.ProtoHTTP})
	p.Add(&models.Proxy{ID: "a2", State: models.StateAlive, HealthScore: 0.7, Protocol: models.ProtoHTTP})
	p.Add(&models.Proxy{ID: "a3", State: models.StateAlive, HealthScore: 0.8, Protocol: models.ProtoSOCKS5})
	p.Add(&models.Proxy{ID: "v1", State: models.StateValidating, Protocol: models.ProtoHTTP})
	p.Add(&models.Proxy{ID: "d1", State: models.StateDead, LastChecked: recentlyDead, Protocol: models.ProtoHTTP})
	p.Add(&models.Proxy{ID: "d2", State: models.StateDead, LastChecked: recentlyDead, Protocol: models.ProtoSOCKS5})
	p.Add(&models.Proxy{ID: "d3", State: models.StateDead, LastChecked: oldDead, Protocol: models.ProtoHTTP})
	p.Add(&models.Proxy{ID: "disc", State: models.StateDiscovered, Protocol: models.ProtoHTTP})

	stats := p.DetailedStats()

	if stats.Total != 8 {
		t.Errorf("Total = %d, want 8", stats.Total)
	}
	if stats.Alive != 3 {
		t.Errorf("Alive = %d, want 3", stats.Alive)
	}
	if stats.Validating != 1 {
		t.Errorf("Validating = %d, want 1", stats.Validating)
	}
	if stats.Dead != 3 {
		t.Errorf("Dead = %d, want 3", stats.Dead)
	}
	if stats.DeadLastHour != 3 {
		t.Errorf("DeadLastHour = %d, want 3 (all dead proxies recorded at time.Now via transition tracking)", stats.DeadLastHour)
	}

	// AvgHealthScore: (0.9 + 0.7 + 0.8) / 3 = 0.8
	const epsilon = 0.001
	expectedAvg := (0.9 + 0.7 + 0.8) / 3.0
	if diff := stats.AvgHealthScore - expectedAvg; diff < -epsilon || diff > epsilon {
		t.Errorf("AvgHealthScore = %f, want ~%f", stats.AvgHealthScore, expectedAvg)
	}

	// Protocols map: only alive proxies count.
	if stats.Protocols["http"] != 2 {
		t.Errorf("protocols[http] = %d, want 2", stats.Protocols["http"])
	}
	if stats.Protocols["socks5"] != 1 {
		t.Errorf("protocols[socks5] = %d, want 1", stats.Protocols["socks5"])
	}
}

func TestDetailedStatsEmpty(t *testing.T) {
	p := NewPool()
	stats := p.DetailedStats()

	if stats.Total != 0 {
		t.Errorf("Total = %d, want 0", stats.Total)
	}
	if stats.Alive != 0 {
		t.Errorf("Alive = %d, want 0", stats.Alive)
	}
	if stats.Protocols == nil {
		t.Error("Protocols map should be initialized (non-nil)")
	}
}

func TestSize(t *testing.T) {
	p := NewPool()
	if p.Size() != 0 {
		t.Errorf("empty pool Size = %d, want 0", p.Size())
	}

	p.Add(&models.Proxy{ID: "a", State: models.StateAlive, Protocol: models.ProtoHTTP})
	if p.Size() != 1 {
		t.Errorf("Size = %d, want 1", p.Size())
	}

	p.Add(&models.Proxy{ID: "b", State: models.StateDead, Protocol: models.ProtoHTTP})
	if p.Size() != 1 {
		t.Errorf("Size = %d, want 1 (dead not counted)", p.Size())
	}

	p.Add(&models.Proxy{ID: "c", State: models.StateAlive, Protocol: models.ProtoSOCKS5})
	if p.Size() != 2 {
		t.Errorf("Size = %d, want 2", p.Size())
	}
}

func TestRemove(t *testing.T) {
	p := NewPool()
	p.Add(&models.Proxy{ID: "a", State: models.StateAlive, Protocol: models.ProtoHTTP})
	p.Add(&models.Proxy{ID: "b", State: models.StateDead, Protocol: models.ProtoHTTP})

	p.Remove("a")
	if _, ok := p.Get("a"); ok {
		t.Error("proxy 'a' should have been removed")
	}
	if p.Size() != 0 {
		t.Errorf("Size = %d, want 0 after removing the only alive", p.Size())
	}

	// Remove non-existent should not panic.
	p.Remove("nonexistent")

	// Remove dead should not affect aliveIDs.
	p.Remove("b")
}

func TestCryptoRandInt(t *testing.T) {
	t.Run("n equals zero returns zero", func(t *testing.T) {
		val, err := cryptoRandInt(0)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if val != 0 {
			t.Errorf("cryptoRandInt(0) = %d, want 0", val)
		}
	})

	t.Run("n is negative returns zero", func(t *testing.T) {
		val, err := cryptoRandInt(-5)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if val != 0 {
			t.Errorf("cryptoRandInt(-5) = %d, want 0", val)
		}
	})

	t.Run("n equals one returns zero", func(t *testing.T) {
		val, err := cryptoRandInt(1)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if val != 0 {
			t.Errorf("cryptoRandInt(1) = %d, want 0", val)
		}
	})

	t.Run("n greater than one returns value in range", func(t *testing.T) {
		const n = 50
		for i := 0; i < 100; i++ {
			val, err := cryptoRandInt(n)
			if err != nil {
				t.Errorf("iteration %d: unexpected error: %v", i, err)
				return
			}
			if val < 0 || val >= n {
				t.Errorf("cryptoRandInt(%d) = %d, want in [0, %d)", n, val, n)
			}
		}
	})
}

func TestCryptoRandFloat64(t *testing.T) {
	t.Run("max equals zero returns zero", func(t *testing.T) {
		val, err := cryptoRandFloat64(0)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if val != 0 {
			t.Errorf("cryptoRandFloat64(0) = %f, want 0", val)
		}
	})

	t.Run("max is negative returns zero", func(t *testing.T) {
		val, err := cryptoRandFloat64(-1.5)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if val != 0 {
			t.Errorf("cryptoRandFloat64(-1.5) = %f, want 0", val)
		}
	})

	t.Run("returns value in range", func(t *testing.T) {
		const maxVal = 10.0
		for i := 0; i < 100; i++ {
			val, err := cryptoRandFloat64(maxVal)
			if err != nil {
				t.Errorf("iteration %d: unexpected error: %v", i, err)
				return
			}
			if val < 0 || val >= maxVal {
				t.Errorf("cryptoRandFloat64(%f) = %f, want in [0, %f)", maxVal, val, maxVal)
			}
		}
	})
}

func TestShuffleSlice(t *testing.T) {
	t.Run("nil slice does not panic", func(t *testing.T) {
		shuffleSlice(nil)
	})

	t.Run("empty slice does not panic", func(t *testing.T) {
		shuffleSlice([]*models.Proxy{})
	})

	t.Run("single element unchanged", func(t *testing.T) {
		p := &models.Proxy{ID: "only"}
		proxies := []*models.Proxy{p}
		shuffleSlice(proxies)
		if len(proxies) != 1 || proxies[0].ID != "only" {
			t.Error("single element slice was modified")
		}
	})

	t.Run("multiple elements does not panic", func(t *testing.T) {
		proxies := []*models.Proxy{
			{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}, {ID: "e"},
		}
		shuffleSlice(proxies)
		if len(proxies) != 5 {
			t.Errorf("slice length changed: got %d, want 5", len(proxies))
		}
	})
}

func TestPoolFilter(t *testing.T) {
	tests := []struct {
		name     string
		filter   PoolFilter
		proxy    *models.Proxy
		want     bool
	}{
		{
			name:   "empty filter matches everything",
			filter: PoolFilter{},
			proxy:  &models.Proxy{Protocol: models.ProtoHTTP, LatencyMs: 500},
			want:   true,
		},
		{
			name:   "any protocol matches all",
			filter: PoolFilter{Protocol: "any"},
			proxy:  &models.Proxy{Protocol: models.ProtoSOCKS5},
			want:   true,
		},
		{
			name:   "exact protocol match",
			filter: PoolFilter{Protocol: "http"},
			proxy:  &models.Proxy{Protocol: models.ProtoHTTP},
			want:   true,
		},
		{
			name:   "protocol mismatch",
			filter: PoolFilter{Protocol: "socks5"},
			proxy:  &models.Proxy{Protocol: models.ProtoHTTP},
			want:   false,
		},
		{
			name:   "latency under max",
			filter: PoolFilter{MaxLatencyMs: 1000},
			proxy:  &models.Proxy{LatencyMs: 500},
			want:   true,
		},
		{
			name:   "latency over max",
			filter: PoolFilter{MaxLatencyMs: 100},
			proxy:  &models.Proxy{LatencyMs: 500},
			want:   false,
		},
		{
			name:   "max latency zero means no filter",
			filter: PoolFilter{MaxLatencyMs: 0},
			proxy:  &models.Proxy{LatencyMs: 9999},
			want:   true,
		},
		{
			name:   "latency exactly at max",
			filter: PoolFilter{MaxLatencyMs: 500},
			proxy:  &models.Proxy{LatencyMs: 500},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.filter.matches(tt.proxy)
			if got != tt.want {
				t.Errorf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
