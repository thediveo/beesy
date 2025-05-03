//go:generate bpf2go -go-package beesy beesy prociter.bpf.c -- -I./_headers

package beesy
