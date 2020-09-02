你好！
很冒昧用这样的方式来和你沟通，如有打扰请忽略我的提交哈。我是光年实验室（gnlab.com）的HR，在招Golang开发工程师，我们是一个技术型团队，技术氛围非常好。全职和兼职都可以，不过最好是全职，工作地点杭州。
我们公司是做流量增长的，Golang负责开发SAAS平台的应用，我们做的很多应用是全新的，工作非常有挑战也很有意思，是国内很多大厂的顾问。
如果有兴趣的话加我微信：13515810775  ，也可以访问 https://gnlab.com/，联系客服转发给HR。
# gobpf

[![Build Status](https://semaphoreci.com/api/v1/alban/gobpf-2/branches/master/badge.svg)](https://semaphoreci.com/alban/gobpf-2) [![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/iovisor/gobpf)

This repository provides go bindings for the [bcc framework](https://github.com/iovisor/bcc)
as well as low-level routines to load and use eBPF programs from .elf
files.

gobpf is in early stage, but usable. Input and contributions are very much welcome.

We recommend to vendor gobpf and pin its version as the API probably
undergoes change during development.

## Requirements

eBPF requires a recent Linux kernel. A good feature list can be found here:
https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md

### `github.com/iovisor/gobpf/bcc`

Install the latest released version of [libbcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
(either by package or source).

### `github.com/iovisor/gobpf/elf`

#### Building ELF object files

To build ELF object files for usage with the elf package, you must use distinct
sections (`SEC("...")`). Currently supported are:

* `kprobe/...`
* `cgroup/skb`
* `cgroup/sock`
* `maps/...`
* `socket...`
* `tracepoint...`

Map definitions must correspond to `bpf_map_def` from [elf.go](https://github.com/iovisor/gobpf/blob/master/elf/elf.go)
Otherwise you will encounter an error like `only one map with size 280 bytes allowed per section (check bpf_map_def)`.

The [Cilium](https://github.com/cilium/cilium) BPF docs contain helpful info
for using clang/LLVM to compile programs into elf object files:
https://cilium.readthedocs.io/en/latest/bpf/#llvm

See `tests/dummy.c` for a minimal dummy and https://github.com/weaveworks/tcptracer-bpf
for a real world example.

## Examples

Example code can be found in the `examples/` directory, e.g.

```
sudo -E go run examples/bcc/perf/perf.go
```

## Tests

The `semaphore.sh` script can be used to run the tests in rkt stage1-kvm
containers on different kernel versions. To run all tests on the host system,
use `go test` as follows:

```
go test -tags integration -v ./...
```
