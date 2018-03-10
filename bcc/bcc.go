package bcc

/*
#cgo pkg-config: libbcc
#cgo LDFLAGS: -L/usr/local/lib
#cgo CFLAGS: -I/usr/local/include -I/usr/local/include/bcc/compat
#include <stdint.h>
#include <sys/types.h>
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>

*/
import "C"
