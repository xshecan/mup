package measure

import (
	"testing"
	"time"
)

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

// sendAnswer sends sequence s at second sec and answers it after rtt.
func sendAnswer(p *Probes, s uint32, sec float64, rtt time.Duration) {
	p.Sent(s, at(sec))
	p.Answered(s, at(sec).Add(rtt))
}

func TestProbesLossWithLostProbes(t *testing.T) {
	var p Probes
	for i := 0; i < 10; i++ {
		if i%5 == 4 { // two lost
			p.Sent(uint32(i), at(float64(i)))
			continue
		}
		sendAnswer(&p, uint32(i), float64(i), ms(20))
	}
	loss, ok := p.LossPercent(at(20))
	if !ok || !near(loss, 20) {
		t.Fatalf("got %v, %v", loss, ok)
	}
}

func TestProbesNoLoss(t *testing.T) {
	var p Probes
	for i := 0; i < 8; i++ {
		sendAnswer(&p, uint32(i), float64(i), ms(10))
	}
	loss, ok := p.LossPercent(at(10))
	if !ok || loss != 0 {
		t.Fatalf("got %v, %v", loss, ok)
	}
}

func TestProbesAnsweredTwice(t *testing.T) {
	var p Probes
	p.Sent(1, at(0))
	rtt, ok := p.Answered(1, at(0).Add(ms(30)))
	if !ok || rtt != ms(30) {
		t.Fatalf("first: %v, %v", rtt, ok)
	}
	if _, ok := p.Answered(1, at(0).Add(ms(90))); ok {
		t.Fatal("second answer must not count")
	}
	if last, _ := p.RTTLast(); last != ms(30) {
		t.Fatalf("last %v, want the first answer", last)
	}
}

func TestProbesUnknownSequence(t *testing.T) {
	var p Probes
	p.Sent(1, at(0))
	if _, ok := p.Answered(2, at(1)); ok {
		t.Fatal("unknown sequence must not count")
	}
	if _, ok := p.LossPercent(at(10)); ok {
		t.Fatal("no answer ever")
	}
}

func TestProbesSentTwiceIgnored(t *testing.T) {
	var p Probes
	p.Sent(1, at(0))
	p.Sent(1, at(5))
	if len(p.list) != 1 {
		t.Fatalf("list %d", len(p.list))
	}
	if rtt, _ := p.Answered(1, at(1)); rtt != time.Second {
		t.Fatalf("rtt %v, want one second from the first send", rtt)
	}
}

func TestProbesNegativeRTTClamps(t *testing.T) {
	var p Probes
	p.Sent(1, at(5))
	rtt, ok := p.Answered(1, at(4))
	if !ok || rtt != 0 {
		t.Fatalf("got %v, %v", rtt, ok)
	}
}

func TestProbesLateAnswerCounts(t *testing.T) {
	var p Probes
	for i := 0; i < 5; i++ {
		p.Sent(uint32(i), at(float64(i)))
	}
	p.Answered(0, at(0).Add(5*time.Second))
	loss, ok := p.LossPercent(at(10))
	if !ok || !near(loss, 80) {
		t.Fatalf("got %v, %v", loss, ok)
	}
}

func TestProbesTimeoutBoundary(t *testing.T) {
	var p Probes
	// four answered probes long ago and one answered to open the tracker
	for i := 0; i < 5; i++ {
		sendAnswer(&p, uint32(i), float64(i), ms(10))
	}
	p.Sent(100, at(20))
	// younger than the timeout, unanswered probe is not complete
	loss, ok := p.LossPercent(at(20).Add(ProbeTimeout - time.Nanosecond))
	if !ok || loss != 0 {
		t.Fatalf("before the timeout: %v, %v", loss, ok)
	}
	// exactly at the timeout it is complete and lost
	loss, ok = p.LossPercent(at(20).Add(ProbeTimeout))
	if !ok || !near(loss, 100.0/6) {
		t.Fatalf("at the timeout: %v, %v", loss, ok)
	}
}

func TestProbesFewerThanFiveComplete(t *testing.T) {
	var p Probes
	for i := 0; i < 4; i++ {
		sendAnswer(&p, uint32(i), float64(i), ms(10))
	}
	if _, ok := p.LossPercent(at(10)); ok {
		t.Fatal("four complete probes give no value")
	}
	sendAnswer(&p, 4, 4, ms(10))
	if _, ok := p.LossPercent(at(10)); !ok {
		t.Fatal("five complete probes give a value")
	}
}

func TestProbesNoAnswerEver(t *testing.T) {
	var p Probes
	for i := 0; i < 30; i++ {
		p.Sent(uint32(i), at(float64(i)))
	}
	if _, ok := p.LossPercent(at(40)); ok {
		t.Fatal("no answer ever must give no value")
	}
}

func TestProbesEverAnsweredSurvivesPruning(t *testing.T) {
	var p Probes
	sendAnswer(&p, 0, 0, ms(10))
	for i := 1; i <= 10; i++ {
		p.Sent(uint32(i), at(100+float64(i)))
	}
	if len(p.list) != 10 {
		t.Fatalf("list %d, old probe is not pruned", len(p.list))
	}
	loss, ok := p.LossPercent(at(120))
	if !ok || !near(loss, 100) {
		t.Fatalf("got %v, %v", loss, ok)
	}
}

func TestProbesRTT(t *testing.T) {
	var p Probes
	sendAnswer(&p, 1, 0, ms(10))
	sendAnswer(&p, 2, 1, ms(30))
	sendAnswer(&p, 3, 2, ms(20))
	avg, ok := p.RTTAvg(at(5))
	if !ok || avg != ms(20) {
		t.Fatalf("avg %v, %v", avg, ok)
	}
	last, ok := p.RTTLast()
	if !ok || last != ms(20) {
		t.Fatalf("last %v, %v", last, ok)
	}
	jit, ok := p.RTTJitter(at(5))
	if !ok || jit != ms(15) {
		t.Fatalf("jitter %v, %v", jit, ok)
	}
}

func TestProbesRTTLastByAnswerTime(t *testing.T) {
	var p Probes
	p.Sent(1, at(0))
	p.Sent(2, at(1))
	p.Answered(2, at(1).Add(ms(40)))
	p.Answered(1, at(1).Add(ms(100))) // later answer, older probe
	last, ok := p.RTTLast()
	if !ok || last != ms(1100) {
		t.Fatalf("last %v, %v", last, ok)
	}
}

func TestProbesRTTNone(t *testing.T) {
	var p Probes
	p.Sent(1, at(0))
	if _, ok := p.RTTAvg(at(1)); ok {
		t.Fatal("avg")
	}
	if _, ok := p.RTTLast(); ok {
		t.Fatal("last")
	}
	if _, ok := p.RTTJitter(at(1)); ok {
		t.Fatal("jitter")
	}
	sendAnswer(&p, 2, 1, ms(5))
	if _, ok := p.RTTJitter(at(2)); ok {
		t.Fatal("one answered probe has no pair")
	}
}

func TestProbesJitterBrokenByLoss(t *testing.T) {
	var p Probes
	sendAnswer(&p, 1, 0, ms(10))
	p.Sent(2, at(1)) // lost
	sendAnswer(&p, 3, 2, ms(50))
	if _, ok := p.RTTJitter(at(5)); ok {
		t.Fatal("a lost probe between breaks the row")
	}
	sendAnswer(&p, 4, 3, ms(30))
	jit, ok := p.RTTJitter(at(5))
	if !ok || jit != ms(20) {
		t.Fatalf("jitter %v, %v", jit, ok)
	}
}

func TestProbesWindowPruning(t *testing.T) {
	var p Probes
	sendAnswer(&p, 1, 0, ms(100))
	sendAnswer(&p, 2, 30, ms(10))
	// at 61 s the first probe is outside the window but still stored
	avg, ok := p.RTTAvg(at(61))
	if !ok || avg != ms(10) {
		t.Fatalf("avg %v, %v", avg, ok)
	}
	// a newer Sent drops probes older than the window
	p.Sent(3, at(65))
	if len(p.list) != 2 {
		t.Fatalf("list %d, want 2", len(p.list))
	}
	// the last RTT outlives pruning
	if last, ok := p.RTTLast(); !ok || last != ms(10) {
		t.Fatalf("last %v, %v", last, ok)
	}
}

func TestProbesSequenceWrap(t *testing.T) {
	var p Probes
	seqs := []uint32{0xFFFFFFFE, 0xFFFFFFFF, 0, 1}
	rtts := []int{10, 20, 40, 10}
	for i, s := range seqs {
		sendAnswer(&p, s, float64(i), ms(rtts[i]))
	}
	jit, ok := p.RTTJitter(at(10))
	if !ok || jit != ms(20) {
		t.Fatalf("jitter %v, %v", jit, ok)
	}
}

func TestProbesCap(t *testing.T) {
	var p Probes
	for i := 0; i < 2000; i++ {
		p.Sent(uint32(i), at(float64(i)*0.001))
	}
	if len(p.list) > maxProbes {
		t.Fatalf("list %d over the cap", len(p.list))
	}
}
