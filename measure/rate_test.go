package measure

import "testing"

func TestRateBasic(t *testing.T) {
	var r Rate
	r.Sample(0, 0, at(0))
	r.Sample(1000, 1500000, at(10))
	pps, bps := r.Rate(at(10))
	if !near(pps, 100) || !near(bps, 1200000) {
		t.Fatalf("got %v, %v", pps, bps)
	}
}

func TestRateTooFewOrTooClose(t *testing.T) {
	var r Rate
	if pps, bps := r.Rate(at(0)); pps != 0 || bps != 0 {
		t.Fatal("empty")
	}
	r.Sample(0, 0, at(0))
	if pps, bps := r.Rate(at(0)); pps != 0 || bps != 0 {
		t.Fatal("one sample")
	}
	r.Sample(100, 100, at(0.9))
	if pps, bps := r.Rate(at(0.9)); pps != 0 || bps != 0 {
		t.Fatal("under one second apart")
	}
	r.Sample(200, 200, at(1))
	if pps, _ := r.Rate(at(1)); !near(pps, 200) {
		t.Fatalf("exactly one second: %v", pps)
	}
}

func TestRateStale(t *testing.T) {
	var r Rate
	r.Sample(0, 0, at(0))
	r.Sample(1000, 1000, at(5))
	if pps, _ := r.Rate(at(14)); !near(pps, 200) {
		t.Fatalf("inside: %v", pps)
	}
	if pps, bps := r.Rate(at(15.1)); pps != 0 || bps != 0 {
		t.Fatal("newest is too old")
	}
}

func TestRateRestart(t *testing.T) {
	var r Rate
	r.Sample(1000, 1000, at(0))
	r.Sample(2000, 2000, at(5))
	r.Sample(10, 10, at(6)) // counter started again
	if pps, bps := r.Rate(at(6)); pps != 0 || bps != 0 {
		t.Fatal("one sample after a restart")
	}
	r.Sample(310, 310, at(9))
	pps, bps := r.Rate(at(9))
	if !near(pps, 100) || !near(bps, 800) {
		t.Fatalf("got %v, %v", pps, bps)
	}
}

func TestRateBytesRestart(t *testing.T) {
	var r Rate
	r.Sample(100, 5000, at(0))
	r.Sample(200, 100, at(5)) // bytes went back
	if len(r.samples) != 1 {
		t.Fatalf("samples %d", len(r.samples))
	}
}

func TestRateKeepsSampleBeforeWindow(t *testing.T) {
	var r Rate
	for s := 0; s <= 30; s++ {
		r.Sample(uint64(s*100), uint64(s*100), at(float64(s)))
	}
	// samples at 20 s (just before the window edge at 20) through 30 s
	if len(r.samples) != 11 {
		t.Fatalf("samples %d, want 11", len(r.samples))
	}
	pps, _ := r.Rate(at(30))
	if !near(pps, 100) {
		t.Fatalf("pps %v", pps)
	}
	// the window slides with now: only 25 s .. 30 s plus the sample at 25
	pps, _ = r.Rate(at(33))
	if !near(pps, 100) {
		t.Fatalf("pps %v", pps)
	}
}

func TestRateWindowFollowsRecentTraffic(t *testing.T) {
	var r Rate
	r.Sample(0, 0, at(0))
	r.Sample(1000, 0, at(10)) // 100 pps
	r.Sample(1000, 0, at(20)) // idle
	pps, _ := r.Rate(at(20))
	if pps != 0 {
		t.Fatalf("pps %v, want 0 for the idle window", pps)
	}
}
