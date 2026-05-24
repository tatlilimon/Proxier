package validator

import (
	"math"
	"testing"

	"github.com/tatlilimon/proxier/internal/models"
)

func TestCalcHealthScore(t *testing.T) {
	tests := []struct {
		name          string
		latencyMs     int
		consecutiveOK int
		want          float64
	}{
		{
			name:          "perfect proxy - low latency, high streak",
			latencyMs:     50,
			consecutiveOK: 15,
			want:          1.0,
		},
		{
			name:          "low latency, zero streak",
			latencyMs:     50,
			consecutiveOK: 0,
			want:          0.4,
		},
		{
			name:          "max latency, max streak",
			latencyMs:     5000,
			consecutiveOK: 20,
			want:          0.6,
		},
		{
			name:          "max latency, zero streak",
			latencyMs:     5000,
			consecutiveOK: 0,
			want:          0.0,
		},
		{
			name:          "latency exactly at 100ms boundary",
			latencyMs:     100,
			consecutiveOK: 10,
			want:          1.0,
		},
		{
			name:          "latency at 100ms, streak 5",
			latencyMs:     100,
			consecutiveOK: 5,
			want:          0.7,
		},
		{
			name:          "latency at 100ms, streak 3",
			latencyMs:     100,
			consecutiveOK: 3,
			want:          0.58,
		},
		{
			name:          "mid latency, mid streak",
			latencyMs:     2550,
			consecutiveOK: 5,
			want:          0.5*0.4 + 0.5*0.6,
		},
		{
			name:          "mid latency 1ms above 100",
			latencyMs:     101,
			consecutiveOK: 10,
			want:          (1.0 - 1.0/4900.0)*0.4 + 1.0*0.6,
		},
		{
			name:          "mid latency 1ms below 5000",
			latencyMs:     4999,
			consecutiveOK: 10,
			want:          (1.0 - 4899.0/4900.0)*0.4 + 1.0*0.6,
		},
		{
			name:          "latency at midpoint (2550ms), streak 0",
			latencyMs:     2550,
			consecutiveOK: 0,
			want:          0.5 * 0.4,
		},
		{
			name:          "latency at midpoint, streak 10",
			latencyMs:     2550,
			consecutiveOK: 10,
			want:          0.5*0.4 + 1.0*0.6,
		},
		{
			name:          "streak exactly at cap boundary (10)",
			latencyMs:     200,
			consecutiveOK: 10,
			want:          latencyScore(200)*0.4 + 1.0*0.6,
		},
		{
			name:          "streak just below cap (9)",
			latencyMs:     200,
			consecutiveOK: 9,
			want:          latencyScore(200)*0.4 + 0.9*0.6,
		},
		{
			name:          "zero latency, zero streak",
			latencyMs:     0,
			consecutiveOK: 0,
			want:          0.4,
		},
		{
			name:          "above 5000ms treated as 0 latency score",
			latencyMs:     6000,
			consecutiveOK: 5,
			want:          0.3,
		},
		{
			name:          "extreme latency, extreme streak",
			latencyMs:     10000,
			consecutiveOK: 100,
			want:          0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{}
			p := &models.Proxy{
				LatencyMs:     tt.latencyMs,
				ConsecutiveOK: tt.consecutiveOK,
			}

			got := v.calcHealthScore(p)

			if math.Abs(got-tt.want) > 0.0001 {
				t.Errorf("calcHealthScore(latency=%d, ok=%d) = %.6f, want %.6f (diff=%.6f)",
					tt.latencyMs, tt.consecutiveOK, got, tt.want, math.Abs(got-tt.want))
			}
		})
	}
}

func latencyScore(ms int) float64 {
	switch {
	case ms <= 100:
		return 1.0
	case ms >= 5000:
		return 0.0
	default:
		return 1.0 - float64(ms-100)/4900.0
	}
}

func TestCalcHealthScore_Range(t *testing.T) {
	v := &Validator{}

	for lat := 0; lat <= 5000; lat += 250 {
		for ok := 0; ok <= 15; ok++ {
			p := &models.Proxy{
				LatencyMs:     lat,
				ConsecutiveOK: ok,
			}
			score := v.calcHealthScore(p)

			if score < 0.0 {
				t.Errorf("latency=%d, ok=%d: score=%.4f < 0.0", lat, ok, score)
			}
			if score > 1.0 {
				t.Errorf("latency=%d, ok=%d: score=%.4f > 1.0", lat, ok, score)
			}
		}
	}
}
