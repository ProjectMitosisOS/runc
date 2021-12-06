// +build linux

package main

/*
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

int
sendfds(int s, int *fds, int fdcount); // defined in fork.go

int
unlock(int fd) {
	// unlock the execution of the child
	char c = 'a';
	int ret = send(fd, &c, sizeof(c), 0);
	return ret;
}

int
getSockFD(char *sockPath) {
	int s, len;
	struct sockaddr_un remote;

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return -1;
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, sockPath);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		return -1;
	}
	return s;
}

int closeSockFD(int s) {
	close(s);
}

int
sendMultipleFDsWithFD(int s, int chrootFD, int utsNamespaceFD, int pidNamespaceFD, int ipcNamespaceFD, int mntNamespaceFD) {
	int fds[5];
	fds[0] = chrootFD;
	fds[1] = utsNamespaceFD;
	fds[2] = pidNamespaceFD;
	fds[3] = ipcNamespaceFD;
	fds[4] = mntNamespaceFD;

	if (sendfds(s, fds, 5) == -1) {
		return -1;
	}

	char pid_arr[20];
	memset(pid_arr, 0, sizeof(pid_arr));
	if (read(s, pid_arr, 20) < 0) {
		return -1;
	}

	int pid = atoi(pid_arr);
	return pid;
}

// Send multiple FDs to the unix socket
int
sendMultipleFDs(char *sockPath, int chrootFD, int utsNamespaceFD, int pidNamespaceFD, int ipcNamespaceFD, int mntNamespaceFD) {
	// Connect to server via socket.
	int s, len, ret;
	struct sockaddr_un remote;

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return -1;
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, sockPath);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		return -1;
	}

	int fds[5];
	fds[0] = chrootFD;
	fds[1] = utsNamespaceFD;
	fds[2] = pidNamespaceFD;
	fds[3] = ipcNamespaceFD;
	fds[4] = mntNamespaceFD;

	if (sendfds(s, fds, 5) == -1) {
		return -1;
	}

	char pid_arr[20];
	memset(pid_arr, 0, sizeof(pid_arr));
	if (read(s, pid_arr, 20) < 0) {
		return -1;
	}

	int pid = atoi(pid_arr);

	if(close(s) == -1) {
		return -1;
	}

	return pid;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/urfave/cli"
)

var fork2ContainerCommand = cli.Command{
	Name:        "fork2container",
	Usage:       "fork a process and land it in a container",
	ArgsUsage:   `TODO`,
	Description: `TODO`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "zygote",
			Value: "",
			Usage: `the container ID of the zygote container`,
		},
		cli.StringFlag{
			Name:  "target",
			Value: "",
			Usage: `the container ID of the target container to land the new process`,
		},
		cli.StringFlag{
			Name:  "fork-socket",
			Value: "rootfs/fork.sock",
			Usage: `the relative path to the fork socket in the zygote container according to the bundle path`,
		},
	},
	Action: func(context *cli.Context) error {
		targetContainerID := context.String("target")
		if targetContainerID == "" {
			return errors.New("target container not specified")
		}
		zygoteContainerID := context.String("zygote")
		if zygoteContainerID == "" {
			return errors.New("zygote container not specified")
		}
		forkSocketPath := context.String("fork-socket")
		if forkSocketPath == "" {
			return errors.New("fork socket not specified")
		}
		targetContainer, err := getContainerByID(context, targetContainerID)
		if err != nil {
			return err
		}
		zygoteContainer, err := getContainerByID(context, zygoteContainerID)
		if err != nil {
			return err
		}
		targetCgroupManager := targetContainer.GetCgroupsManager()
		if targetCgroupManager == nil {
			return errors.New("cgroups manager is nil")
		}
		targetContainerState, err := targetContainer.State()
		if err != nil {
			return err
		}
		zygoteContainerState, err := zygoteContainer.State()
		if err != nil {
			return err
		}
		if targetContainerState == nil {
			return errors.New("container state is nil")
		}
		// fmt.Println(targetContainerState.InitProcessPid)

		// Open required namespace fds
		utsNamespace := "/proc/" + fmt.Sprint(targetContainerState.InitProcessPid) + "/ns/uts"
		pidNamespace := "/proc/" + fmt.Sprint(targetContainerState.InitProcessPid) + "/ns/pid"
		ipcNamespace := "/proc/" + fmt.Sprint(targetContainerState.InitProcessPid) + "/ns/ipc"
		mntNamespace := "/proc/" + fmt.Sprint(targetContainerState.InitProcessPid) + "/ns/mnt"
		utsNamespaceFd, err := os.Open(utsNamespace)
		if err != nil {
			return err
		}
		defer utsNamespaceFd.Close()
		pidNamespaceFd, err := os.Open(pidNamespace)
		if err != nil {
			return err
		}
		defer pidNamespaceFd.Close()
		ipcNamespaceFd, err := os.Open(ipcNamespace)
		if err != nil {
			return err
		}
		defer ipcNamespaceFd.Close()
		mntNamespaceFd, err := os.Open(mntNamespace)
		if err != nil {
			return err
		}
		defer mntNamespaceFd.Close()

		targetContainerBundle, _ := utils.Annotations(targetContainerState.Config.Labels)
		targetContainerRootfs, err := securejoin.SecureJoin(targetContainerBundle, "rootfs")
		if err != nil {
			return err
		}
		// fmt.Println(targetContainerRootfs)
		targetContainerRootfsFd, err := os.Open(targetContainerRootfs)
		if err != nil {
			return err
		}
		defer targetContainerRootfsFd.Close()

		// Find the path to the zygote container fork socket
		zygoteContainerBundle, _ := utils.Annotations(zygoteContainerState.Config.Labels)
		zygoteContainerForkSocketPath, err := securejoin.SecureJoin(zygoteContainerBundle, forkSocketPath)
		// fmt.Println(zygoteContainerForkSocketPath)

		// Send the fds to the socket
		pid, fd, err := invokeMultipleFDs(zygoteContainerForkSocketPath, targetContainerRootfsFd, utsNamespaceFd, pidNamespaceFd, ipcNamespaceFd, mntNamespaceFd)
		if err != nil {
			return err
		}
		// fmt.Println(pid)
		// t0 := time.Now().UnixNano()
		err = (*targetCgroupManager).Apply(pid)
		if err != nil {
			return err
		}
		ret := C.unlock(C.int(fd))
		if ret < 0 {
			return errors.New("fail to write unlock signal to socket")
		}
		// t1 := time.Now().UnixNano()
		// fmt.Println(pid, " after applying this pid the cgroups")
		// fmt.Printf("apply cgroup %dns\n", t1-t0)
		// fmt.Printf("total time %dns\n", t1-start)
		fmt.Println(pid)
		waitForExit(pid)
		C.closeSockFD(C.int(fd))
		return nil
	},
}

func waitForExit(pid int) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	for true {
		err = process.Signal(syscall.Signal(0))
		if err != nil {
			break
		}
	}
	return
}

func invokeMultipleFDs(socketPath string, rootDir *os.File, utsNamespaceFd *os.File, pidNamespaceFd *os.File, ipcNamespaceFd *os.File, mntNamespaceFd *os.File) (int, int, error) {
	cSock := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cSock))
	fd, err := C.getSockFD(cSock)
	if err != nil {
		return -1, -1, err
	}
	pid, err := C.sendMultipleFDsWithFD(C.int(fd), C.int(rootDir.Fd()), C.int(utsNamespaceFd.Fd()), C.int(pidNamespaceFd.Fd()), C.int(ipcNamespaceFd.Fd()), C.int(mntNamespaceFd.Fd()))
	if err != nil {
		C.closeSockFD(C.int(fd))
		return -1, -1, err
	}
	return int(pid), int(fd), nil
}
