package dataplane

import (
	"testing"
	"unsafe"
)

func TestGeneratedABISizes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "client key", got: unsafe.Sizeof(mupClientKeyV1{}), want: 16},
		{name: "client config", got: unsafe.Sizeof(mupClientConfigV1{}), want: 16},
		{name: "path group", got: unsafe.Sizeof(mupPathGroupV1{}), want: 8},
		{name: "server config", got: unsafe.Sizeof(mupServerConfigV1{}), want: 16},
		{name: "server route key", got: unsafe.Sizeof(mupServerRouteKeyV1{}), want: 24},
		{name: "server route value", got: unsafe.Sizeof(mupServerRouteValueV1{}), want: 32},
		{name: "registered path key", got: unsafe.Sizeof(mupRegisteredPathKeyV1{}), want: 12},
		{name: "server reverse value", got: unsafe.Sizeof(mupServerReverseValueV1{}), want: 56},
		{name: "registered path value", got: unsafe.Sizeof(mupRegisteredPathValueV1{}), want: 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("size = %d, want %d", tt.got, tt.want)
			}
		})
	}
}
