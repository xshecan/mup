package measure

import (
	"testing"
	"time"
)

func TestRTTsAvgJitterLast(t *testing.T) {
	var r RTTs
	if _, ok := r.Avg(at(0)); ok {
		t.Fatal("empty avg")
	}
	if _, ok := r.Last(); ok {
		t.Fatal("empty last")
	}
	r.Add(ms(10), at(0))
	if _, ok := r.Jitter(at(0)); ok {
		t.Fatal("one sample has no jitter")
	}
	r.Add(ms(30), at(1))
	r.Add(ms(20), at(2))
	avg, ok := r.Avg(at(3))
	if !ok || avg != ms(20) {
		t.Fatalf("avg %v, %v", avg, ok)
	}
	jit, ok := r.Jitter(at(3))
	if !ok || jit != ms(15) {
		t.Fatalf("jitter %v, %v", jit, ok)
	}
	last, ok := r.Last()
	if !ok || last != ms(20) {
		t.Fatalf("last %v, %v", last, ok)
	}
}

func TestRTTsWindow(t *testing.T) {
	var r RTTs
	r.Add(ms(100), at(0))
	r.Add(ms(10), at(30))
	r.Add(ms(20), at(40))
	// at 60 s the first sample sits exactly on the edge
	avg, _ := r.Avg(at(60))
	if want := (ms(100) + ms(10) + ms(20)) / 3; avg != want {
		t.Fatalf("edge avg %v, want %v", avg, want)
	}
	avg, ok := r.Avg(at(60).Add(time.Millisecond))
	if !ok || avg != ms(15) {
		t.Fatalf("avg %v, %v", avg, ok)
	}
	jit, ok := r.Jitter(at(60).Add(time.Millisecond))
	if !ok || jit != ms(10) {
		t.Fatalf("jitter %v, %v", jit, ok)
	}
	if _, ok := r.Avg(at(200)); ok {
		t.Fatal("all samples are old")
	}
	if last, ok := r.Last(); !ok || last != ms(20) {
		t.Fatalf("last %v, %v", last, ok)
	}
}

func TestRTTsPruneAndCap(t *testing.T) {
	var r RTTs
	r.Add(ms(1), at(0))
	r.Add(ms(2), at(100))
	if len(r.samples) != 1 {
		t.Fatalf("samples %d", len(r.samples))
	}
	for i := 0; i < 2000; i++ {
		r.Add(ms(i), at(200+float64(i)*0.001))
	}
	if len(r.samples) > maxRTTs {
		t.Fatalf("samples %d over the cap", len(r.samples))
	}
}
