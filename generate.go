//go:generate bpf2go -go-package beesy -type procstatus beesy prociter.bpf.c -- -I./_headers

package beesy
