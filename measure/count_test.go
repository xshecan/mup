package measure

import "testing"

func TestEncodeDecodeCount(t *testing.T) {
	tests := []struct {
		name    string
		packets uint64
		code    uint32
	}{
		{"zero", 0, 1},
		{"one", 1, 2},
		{"last before wrap", 0xFFFFFFFE, 0xFFFFFFFF},
		{"wrap", 0xFFFFFFFF, 1},
		{"after wrap", 0xFFFFFFFF + 5, 6},
		{"large", 3*0xFFFFFFFF + 7, 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := EncodeCount(tt.packets)
			if code != tt.code {
				t.Fatalf("EncodeCount(%d) = %d, want %d", tt.packets, code, tt.code)
			}
			count, ok := DecodeCount(code)
			if !ok {
				t.Fatalf("DecodeCount(%d) not ok", code)
			}
			if want := uint32(tt.packets % 0xFFFFFFFF); count != want {
				t.Fatalf("DecodeCount(%d) = %d, want %d", code, count, want)
			}
		})
	}
}

func TestDecodeCountZeroIsNoCount(t *testing.T) {
	if c, ok := DecodeCount(0); ok || c != 0 {
		t.Fatalf("DecodeCount(0) = %d, %v", c, ok)
	}
}

func TestCountDelta(t *testing.T) {
	tests := []struct {
		name         string
		newer, older uint32
		want         uint32
	}{
		{"same", 5, 5, 0},
		{"forward", 15, 5, 10},
		{"across the wrap", 3, 0xFFFFFFFE, 4},
		{"wrap to zero", 0, 0xFFFFFFFE, 1},
		{"backward", 5, 15, 0xFFFFFFFF - 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CountDelta(tt.newer, tt.older); got != tt.want {
				t.Fatalf("CountDelta(%d, %d) = %d, want %d", tt.newer, tt.older, got, tt.want)
			}
		})
	}
}
