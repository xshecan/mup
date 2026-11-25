package measure

import (
	"testing"
	"time"
)

func lp(id, prio int, rtt time.Duration) LatencyPath {
	return LatencyPath{ID: id, Priority: prio, Usable: true, RTT: rtt}
}

func TestLatencyFirstPick(t *testing.T) {
	tests := []struct {
		name  string
		paths []LatencyPath
		want  int
		ok    bool
	}{
		{"lowest rtt", []LatencyPath{lp(1, 0, ms(30)), lp(2, 1, ms(10)), lp(3, 2, ms(20))}, 2, true},
		{"unknown ranks last", []LatencyPath{lp(1, 0, 0), lp(2, 1, ms(50))}, 2, true},
		{"unknown by priority", []LatencyPath{lp(1, 2, 0), lp(2, 1, 0), lp(3, 3, ms(90))}, 3, true},
		{"all unknown by priority", []LatencyPath{lp(1, 2, 0), lp(2, 1, 0), lp(3, 3, 0)}, 2, true},
		{"tie by priority", []LatencyPath{lp(1, 2, ms(10)), lp(2, 1, ms(10))}, 2, true},
		{"tie by id", []LatencyPath{lp(5, 1, ms(10)), lp(4, 1, ms(10))}, 4, true},
		{"unusable skipped", []LatencyPath{{ID: 1, RTT: ms(1)}, lp(2, 1, ms(10))}, 2, true},
		{"none usable", []LatencyPath{{ID: 1, RTT: ms(1)}}, 0, false},
		{"empty", nil, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c LatencyChooser
			got, ok := c.Choose(tt.paths, at(0))
			if got != tt.want || ok != tt.ok {
				t.Fatalf("got %d, %v", got, ok)
			}
		})
	}
}

// lstep is one evaluation: the paths and the id that is expected.
type lstep struct {
	sec   float64
	paths []LatencyPath
	want  int
}

func TestLatencySwitching(t *testing.T) {
	tests := []struct {
		name  string
		steps []lstep
	}{
		{"margin: 5 percent faster does not take over", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(100))}, 1},
			{1, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(95))}, 1},
			{100, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(95))}, 1},
		}},
		{"margin: exactly 10 percent does not qualify", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(100))}, 1},
			{1, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(90))}, 1},
			{100, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(90))}, 1},
		}},
		{"floor: 1.5 ms faster at 10 ms does not qualify", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, ms(10))}, 1},
			{1, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, 8500*time.Microsecond)}, 1},
			{100, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, 8500*time.Microsecond)}, 1},
		}},
		{"floor: 2.5 ms faster at 10 ms qualifies", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, ms(10))}, 1},
			{1, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, 7500*time.Microsecond)}, 1},
			{11, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, 7500*time.Microsecond)}, 2},
		}},
		{"10 s rule: not at 9.9 s, yes at 10 s", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(100))}, 1},
			{1, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(50))}, 1},
			{10.9, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(50))}, 1},
			{11, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(50))}, 2},
		}},
		{"candidate change resets the timer", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(100)), lp(3, 2, ms(100))}, 1},
			{1, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(50)), lp(3, 2, ms(60))}, 1},
			{8, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(60)), lp(3, 2, ms(50))}, 1},
			{12, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(60)), lp(3, 2, ms(50))}, 1},
			{17.9, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(60)), lp(3, 2, ms(50))}, 1},
			{18, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(60)), lp(3, 2, ms(50))}, 3},
		}},
		{"candidate stops being better resets the timer", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(100))}, 1},
			{1, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(50))}, 1},
			{8, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(99))}, 1},
			{9, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(50))}, 1},
			{18.9, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(50))}, 1},
			{19, []LatencyPath{lp(1, 0, ms(100)), lp(2, 1, ms(50))}, 2},
		}},
		{"current becoming unusable switches at once", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, ms(50))}, 1},
			{1, []LatencyPath{{ID: 1, RTT: ms(10)}, lp(2, 1, ms(50)), lp(3, 2, ms(40))}, 3},
		}},
		{"current missing from the list switches at once", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, ms(50))}, 1},
			{1, []LatencyPath{lp(2, 1, ms(50))}, 2},
		}},
		{"no usable path forgets the current", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, ms(50))}, 1},
			{1, []LatencyPath{{ID: 1}, {ID: 2}}, 0},
			{2, []LatencyPath{lp(1, 0, ms(60)), lp(2, 1, ms(50))}, 2},
		}},
		{"current with unknown rtt is replaced after 10 s", []lstep{
			{0, []LatencyPath{lp(1, 0, 0), lp(2, 1, 0)}, 1},
			{1, []LatencyPath{lp(1, 0, 0), lp(2, 1, ms(80))}, 1},
			{10.9, []LatencyPath{lp(1, 0, 0), lp(2, 1, ms(80))}, 1},
			{11, []LatencyPath{lp(1, 0, 0), lp(2, 1, ms(80))}, 2},
		}},
		{"stays when the current is the best", []lstep{
			{0, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, ms(50))}, 1},
			{50, []LatencyPath{lp(1, 0, ms(10)), lp(2, 1, ms(50))}, 1},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c LatencyChooser
			for i, s := range tt.steps {
				got, ok := c.Choose(s.paths, at(s.sec))
				if wantOK := s.want != 0; ok != wantOK || got != s.want {
					t.Fatalf("step %d (t=%v): got %d, %v, want %d", i, s.sec, got, ok, s.want)
				}
			}
		})
	}
}
