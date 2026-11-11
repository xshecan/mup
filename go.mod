module github.com/xshecan/mup

go 1.27.4

require (
	github.com/cilium/ebpf v0.22.0
	go.uber.org/config v1.4.1
	go.uber.org/dig v1.19.0
	go.uber.org/fx v1.24.0
	golang.org/x/sys v0.50.0
)

require (
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
