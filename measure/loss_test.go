package measure

import (
	"math"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func at(sec float64) time.Time {
	return t0.Add(time.Duration(sec * float64(time.Second)))
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// feed marks one frame per second with the given per second send and receive counts.
func feed(l *Loss, startTx, startRx uint32, perSecTx, perSecRx uint32, from, to int) {
	for s := from; s <= to; s++ {
		k := uint32(s - from)
		tx := uint32((uint64(startTx) + uint64(k)*uint64(perSecTx)) % countModulus)
		rx := uint32((uint64(startRx) + uint64(k)*uint64(perSecRx)) % countModulus)
		l.Mark(tx, rx, at(float64(s)))
	}
}

func TestLossZero(t *testing.T) {
	var l Loss
	feed(&l, 0, 0, 100, 100, 0, 10)
	p, ok := l.Percent(ShortWindow, at(10))
	if !ok || !near(p, 0) {
		t.Fatalf("got %v, %v", p, ok)
	}
}

func TestLossTenPercent(t *testing.T) {
	var l Loss
	feed(&l, 0, 0, 100, 90, 0, 10)
	p, ok := l.Percent(ShortWindow, at(10))
	if !ok || !near(p, 10) {
		t.Fatalf("got %v, %v", p, ok)
	}
}

func TestLossReceiverAheadClampsToZero(t *testing.T) {
	var l Loss
	feed(&l, 0, 0, 100, 110, 0, 10)
	p, ok := l.Percent(ShortWindow, at(10))
	if !ok || p != 0 {
		t.Fatalf("got %v, %v", p, ok)
	}
}

func TestLossAllLost(t *testing.T) {
	var l Loss
	l.Mark(0, 0, at(0))
	l.Mark(1000, 0, at(10))
	p, ok := l.Percent(ShortWindow, at(10))
	if !ok || !near(p, 100) {
		t.Fatalf("got %v, %v", p, ok)
	}
}

func TestLossWrapInWindow(t *testing.T) {
	var l Loss
	feed(&l, 0xFFFFFFFE-500, 0xFFFFFFFE-450, 100, 90, 0, 10)
	p, ok := l.Percent(ShortWindow, at(10))
	if !ok || !near(p, 10) {
		t.Fatalf("got %v, %v", p, ok)
	}
}

func TestLossRestart(t *testing.T) {
	var l Loss
	feed(&l, 1000, 1000, 100, 100, 0, 5)
	// the receiver counter starts again far ahead of the sender
	l.Mark(1600, 90000, at(6))
	if len(l.markers) != 1 {
		t.Fatalf("markers %d, a restart keeps only the new one", len(l.markers))
	}
	if _, ok := l.Percent(ShortWindow, at(6)); ok {
		t.Fatal("one marker after a restart must not give a value")
	}
	feed(&l, 1700, 90095, 100, 95, 7, 16)
	p, ok := l.Percent(ShortWindow, at(16))
	if !ok || !near(p, 5) {
		t.Fatalf("got %v, %v", p, ok)
	}
}

func TestLossRestartSlack(t *testing.T) {
	var l Loss
	l.Mark(1000, 1000, at(0))
	// receiver ahead by less than the slack keeps the older markers
	l.Mark(1100, 1100+60, at(10))
	if p, ok := l.Percent(ShortWindow, at(10)); !ok || p != 0 {
		t.Fatalf("got %v, %v", p, ok)
	}
	// receiver ahead by more than the slack is a restart
	var m Loss
	m.Mark(1000, 1000, at(0))
	m.Mark(1100, 1100+200, at(10))
	if _, ok := m.Percent(ShortWindow, at(10)); ok {
		t.Fatal("a restart leaves one marker")
	}
}

func TestLossOutOfOrderIgnored(t *testing.T) {
	var l Loss
	l.Mark(0, 0, at(0))
	l.Mark(1000, 1000, at(10))
	l.Mark(500, 500, at(10.5)) // late frame
	l.Mark(1000, 1000, at(10.6))
	if len(l.markers) != 3 {
		t.Fatalf("markers %d, want 3 (older ignored, equal kept)", len(l.markers))
	}
	p, ok := l.Percent(11*time.Second, at(10.6))
	if !ok || !near(p, 0) {
		t.Fatalf("got %v, %v", p, ok)
	}
}

func TestLossBackwardOneSideIgnored(t *testing.T) {
	var l Loss
	l.Mark(1000, 1000, at(0))
	l.Mark(900, 1100, at(1))
	l.Mark(1100, 900, at(2))
	if len(l.markers) != 1 {
		t.Fatalf("markers %d, want 1", len(l.markers))
	}
}

func TestLossIdlePath(t *testing.T) {
	var l Loss
	feed(&l, 0, 0, 100, 100, 0, 10)
	if _, ok := l.Percent(ShortWindow, at(10)); !ok {
		t.Fatal("expected a value")
	}
	if _, ok := l.Percent(ShortWindow, at(20.5)); ok {
		t.Fatal("idle path must give no value")
	}
	// the long window still sees the old markers
	if _, ok := l.Percent(LongWindow, at(20.5)); ok {
		t.Fatal("span 10s is less than half of 60s")
	}
}

func TestLossTooFewPackets(t *testing.T) {
	var l Loss
	l.Mark(0, 0, at(0))
	l.Mark(49, 49, at(10))
	if _, ok := l.Percent(ShortWindow, at(10)); ok {
		t.Fatal("dtx 49 must give no value")
	}
	l.Mark(50, 50, at(10.5))
	if _, ok := l.Percent(11*time.Second, at(10.5)); !ok {
		t.Fatal("dtx 50 must give a value")
	}
}

func TestLossWindowEdges(t *testing.T) {
	var l Loss
	l.Mark(0, 0, at(0))
	l.Mark(1000, 500, at(10))
	// marker at exactly now-window is included
	p, ok := l.Percent(ShortWindow, at(10))
	if !ok || !near(p, 50) {
		t.Fatalf("edge in: %v, %v", p, ok)
	}
	// one nanosecond later it falls out and one marker is left
	if _, ok := l.Percent(ShortWindow, at(10).Add(time.Nanosecond)); ok {
		t.Fatal("edge out must give no value")
	}
}

func TestLossHalfWindowSpan(t *testing.T) {
	var l Loss
	l.Mark(0, 0, at(0))
	l.Mark(1000, 1000, at(4.9))
	if _, ok := l.Percent(ShortWindow, at(4.9)); ok {
		t.Fatal("span below half a window must give no value")
	}
	var m Loss
	m.Mark(0, 0, at(0))
	m.Mark(1000, 1000, at(5))
	if _, ok := m.Percent(ShortWindow, at(5)); !ok {
		t.Fatal("span of exactly half a window must give a value")
	}
}

func TestLossShortVersusLong(t *testing.T) {
	var l Loss
	// 50 s with 20 percent loss, then 10 s without loss
	feed(&l, 0, 0, 100, 80, 0, 50)
	feed(&l, 5000, 4000, 100, 100, 51, 60)
	short, ok := l.Percent(ShortWindow, at(60))
	if !ok || !near(short, 0) {
		t.Fatalf("short %v, %v", short, ok)
	}
	long, ok := l.Percent(LongWindow, at(60))
	if !ok || long < 15 || long > 20 {
		t.Fatalf("long %v, %v", long, ok)
	}
}

func TestLossPruneAndCap(t *testing.T) {
	var l Loss
	for i := 0; i < 2000; i++ {
		l.Mark(uint32(i), uint32(i), at(float64(i)*0.01))
	}
	if len(l.markers) > maxMarkers {
		t.Fatalf("markers %d over the cap", len(l.markers))
	}
	var m Loss
	feed(&m, 0, 0, 10, 10, 0, 200)
	if len(m.markers) > 62 {
		t.Fatalf("markers %d, old ones are not pruned", len(m.markers))
	}
}

func TestLossReset(t *testing.T) {
	var l Loss
	feed(&l, 0, 0, 100, 100, 0, 10)
	l.Reset()
	if _, ok := l.Percent(ShortWindow, at(10)); ok {
		t.Fatal("reset must clear")
	}
	l.Mark(5, 5, at(11))
	if len(l.markers) != 1 {
		t.Fatal("marker after reset")
	}
}

func TestLossZeroValue(t *testing.T) {
	var l Loss
	if _, ok := l.Percent(ShortWindow, at(0)); ok {
		t.Fatal("empty must give no value")
	}
}

func TestLossCounterThatStartsAgainFromZero(t *testing.T) {
	var l Loss
	feed(&l, 100000, 100000, 100, 100, 0, 10)
	// The receiver starts again from zero, so each marker goes back. The
	// tracker waits for a few markers in a row, then it starts from the
	// newest one.
	l.Mark(101100, 10, at(11))
	l.Mark(101200, 110, at(12))
	if len(l.markers) != 11 {
		t.Fatalf("markers %d, want the 11 old ones while the restart is not sure", len(l.markers))
	}
	l.Mark(101300, 210, at(13))
	if len(l.markers) != 1 || l.markers[0].rx != 210 {
		t.Fatalf("markers = %#v, want only the newest", l.markers)
	}
	feed(&l, 101400, 310, 100, 90, 14, 24)
	p, ok := l.Percent(ShortWindow, at(24))
	if !ok || !near(p, 10) {
		t.Fatalf("got %v, %v, want 10", p, ok)
	}
}
