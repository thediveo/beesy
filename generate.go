//go:generate bpf2go -go-package beesy beesy taskiter.bpf.c -- -I./_headers/cilium-ebpf -I./_headers/libbpf -I./_headers/beesy

package beesy
