package dataplane

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestForwardingProgramsAreNotPassThroughScaffolds(t *testing.T) {
	t.Parallel()

	spec, err := loadMup()
	if err != nil {
		t.Fatalf("loadMup: %v", err)
	}
	tests := []struct {
		name    string
		program *ebpf.ProgramSpec
		helpers []asm.BuiltinFunc
	}{
		{
			name:    "client",
			program: spec.Programs["mup_client_ingress"],
			helpers: []asm.BuiltinFunc{
				asm.FnMapLookupElem,
				asm.FnMapUpdateElem,
				asm.FnMapPopElem,
				asm.FnKtimeGetNs,
				asm.FnFibLookup,
				asm.FnCloneRedirect,
				asm.FnRedirectNeigh,
				asm.FnRingbufReserve,
				asm.FnRingbufSubmit,
			},
		},
		{
			name:    "server",
			program: spec.Programs["mup_server_ingress"],
			helpers: []asm.BuiltinFunc{
				asm.FnMapLookupElem,
				asm.FnMapUpdateElem,
				asm.FnMapPopElem,
				asm.FnKtimeGetNs,
				asm.FnRedirectNeigh,
				asm.FnRingbufReserve,
				asm.FnRingbufSubmit,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.program == nil {
				t.Fatal("program is missing")
			}
			for _, helper := range tt.helpers {
				if !callsHelper(tt.program, helper) {
					t.Errorf("program does not call %s", helper)
				}
			}
		})
	}
}

func TestWireGuardValidationProgramsExist(t *testing.T) {
	t.Parallel()

	spec, err := loadMup()
	if err != nil {
		t.Fatalf("loadMup: %v", err)
	}
	for _, name := range []string{
		"mup_test_validate_local",
		"mup_test_validate_tunneled",
		"mup_test_control",
	} {
		if spec.Programs[name] == nil {
			t.Errorf("missing program %q", name)
		}
	}
}

func callsHelper(program *ebpf.ProgramSpec, helper asm.BuiltinFunc) bool {
	for _, instruction := range program.Instructions {
		if instruction.OpCode.JumpOp() == asm.Call && asm.BuiltinFunc(instruction.Constant) == helper {
			return true
		}
	}
	return false
}
