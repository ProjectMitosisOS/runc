# Quick Start

## Prerequisite

go > 1.13, libseccomp, gcc, ...

## Clone

```bash
git clone https://ipads.se.sjtu.edu.cn:1312/xcontainer/runc.git
git clone https://ipads.se.sjtu.edu.cn:1312/xcontainer/rfork-python-runtime.git rfork
```

**rfork-python-runtime** should be cloned in a short path to avoid possible buffer overflow in the path to unix domain socket.

## Compile and Quick Start

```bash
cd runc && git checkout add-fork-command
make static # Artifact: runc
```

```bash
cd rfork
make base-image base-spin-image # TODO: need to remove the dependency to the val registry
cd benchmarks/concurrent-latency
go build bootstrapRootFS.go
sudo ./bootstrapRootFS 1 10 # prepare 1 rootfs for zygote container and 10 rootfs for app containers. (app container is a container where we place the newly-forked process)

cd .base/container0
sudo runc run -d python-test # this is our zygote container
# The .base/container0 's dir needs to be short, or it may cause a buffer overflow. So we can cp the directory to ~/
cd ../spin0
sudo runc run -d app-test # this is our app container

sudo /path/to/modified/runc fork2container --zygote python-test --target app-test
sudo runc ps app-test # we can see the new process running in the new container
sudo runc exec -t app-test sh # enter the app container
# ps -ef # this will show the running processes, restricted in this container
```

## Cleanup

```bash
sudo runc delete -f app-test
sudo runc delete -f python-test
```

## Quick Benchmark

### Concurrent fork latency

```bash
cd rfork/benchmarks/concurrent-latency
go build concurrentForkContainerLatency.go
sudo ./bootstrapRootFS 1 10
sudo -E RUNC=/path/to/modified/runc ./concurrentForkContainerLatency 1 10 # concurrent ops == 1 && benchmark time == 10
# Output:
# 1137 # the number of the "fork" operation completed in the benchmark time
# 8779759 # average latency in nanoseconds
```

### Concurrent start latency

```bash
cd rfork/benchmarks/concurrent-latency
go build concurrentStartContainerLatency.go
sudo ./bootstrapRootFS 1 10
sudo -E RUNC=/path/to/modified/runc ./concurrentStartContainerLatency 1 10
# similar output
```

### Concurrent unfreeze latency

```bash
cd rfork/benchmarks/concurrent-latency
go build concurrentStartContainerLatency.go
sudo ./bootstrapRootFS 1 10
sudo -E RUNC=/path/to/modified/runc ./concurrentUnfreezeContainerLatency 1 10
# similar output
```

### Enable extra import in zygote or app

Modify bootstrapRootFS.go, add `IMPORT_EXTRA_LIBS_IN_ZYGOTE=1` and `IMPORT_EXTRA_LIBS_IN_APP=1` to the `zygoteConfigJSON`.

```
var zygoteConfigJSON = `...
"env": [
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"TERM=xterm",
			"IMPORT_EXTRA_LIBS_IN_ZYGOTE=1",
			"IMPORT_EXTRA_LIBS_IN_APP=1"
		],
...
```

Recompile bootstrapRootFS.go and rerun the benchmarks.

## Issues

rfork needs to be cloned in directory with a path as short as possible. Otherwise the path to unix socket will overflow the data structure and cause the program to abort.
