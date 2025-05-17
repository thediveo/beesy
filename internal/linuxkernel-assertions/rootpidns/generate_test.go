//go:generate bpf2go -go-package rootpidns_test bee taskiter.bpf.c -- -I../../../_headers/cilium-ebpf -I../../../_headers/libbpf -I../../../_headers/beesy

package rootpidns_test
