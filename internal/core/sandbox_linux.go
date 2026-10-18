//go:build linux

package core

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	capSetpcap          = 8
	capSysAdmin         = 21
	prSetSeccomp        = 22
	prSetSecurebits     = 28
	prSetNoNewPrivs     = 38
	seccompModeFilter   = 2
	secbitsLockedNoRoot = 0x2f
	linuxCapVer3        = 0x20080522
)

var linuxSandboxArch = runtime.GOARCH

func seccompArch(goarch string) (arch, sysSocket, sysConnect, sysBind uint32, err error) {
	switch goarch {
	case "amd64":
		return 0xc000003e, 41, 42, 49, nil
	case "arm64":
		return 0xc00000b7, 198, 203, 200, nil
	default:
		return 0, 0, 0, 0, errors.New("no_network is only supported on linux/amd64 and linux/arm64")
	}
}

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

func init() {
	if len(os.Args) > 1 && os.Args[1] == "-mintrun-linux-sandbox" {
		os.Exit(runLinuxSandbox(os.Args[2:]))
	}
}

// LinuxSandboxSysProcAttr configures cmd to run in a new user and mount namespace with the
// caller's UID and GID mapped and CAP_SYS_ADMIN + CAP_SETPCAP raised as ambient capabilities so
// the re-executed helper can mount tmpfs and /dev/null and then drop all capabilities before
// execing the target command. It is a var so hermetic unit tests can stub it.
var LinuxSandboxSysProcAttr = func(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS
	cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}}
	cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}
	cmd.SysProcAttr.GidMappingsEnableSetgroups = false
	cmd.SysProcAttr.AmbientCaps = []uintptr{capSysAdmin, capSetpcap}
}

func runLinuxSandbox(args []string) int {
	fail := func(code int, msg any) int {
		fmt.Fprintln(os.Stderr, msg)
		return code
	}
	var dirs, files, cmd []string
	noNetwork, seenSep := false, false
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			seenSep, cmd = true, args[i+1:]
			break
		}
		if args[i] == "-no-network" {
			noNetwork = true
			continue
		}
		if i+1 >= len(args) || (args[i] != "-hide-dir" && args[i] != "-hide-file") {
			return fail(126, "invalid sandbox arguments")
		}
		if args[i] == "-hide-dir" {
			dirs = append(dirs, args[i+1])
		} else {
			files = append(files, args[i+1])
		}
		i++
	}
	if !seenSep || len(dirs) == 0 {
		return fail(126, "invalid sandbox arguments")
	}
	if err := setupLinuxSandbox(dirs, files, noNetwork, len(cmd) == 0); err != nil {
		return fail(126, pathCause(err))
	}
	if len(cmd) == 0 {
		return 0
	}
	return fail(127, syscall.Exec(cmd[0], cmd, os.Environ()))
}

func setupLinuxSandbox(dirs, files []string, noNetwork, probeOnly bool) error {
	cwd, err := os.Getwd()
	var arch, sysSocket, sysConnect, sysBind uint32
	if err == nil && noNetwork {
		if arch, sysSocket, sysConnect, sysBind, err = seccompArch(linuxSandboxArch); err == nil {
			err = syscall.Unshare(syscall.CLONE_NEWNET)
		}
	}
	const dirFlags = uintptr(syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
	for i, d := range dirs {
		if err != nil {
			break
		}
		if i == 0 && probeOnly {
			// In CheckPolicy's dry-run probe, mintrun's home may not exist yet (CheckPolicy never
			// writes to disk, rule 16); probe its parent instead.
			if _, stErr := os.Lstat(d); errors.Is(stErr, fs.ErrNotExist) {
				d = filepath.Dir(d)
			}
		}
		if err = syscall.Mount("tmpfs", d, "tmpfs", dirFlags, "size=4k,mode=000"); err == nil {
			err = syscall.Mount("tmpfs", d, "tmpfs", dirFlags|syscall.MS_REMOUNT|syscall.MS_RDONLY, "size=4k,mode=000")
		}
	}
	for _, f := range files {
		if err == nil {
			err = syscall.Mount("/dev/null", f, "", syscall.MS_BIND, "")
		}
	}
	if err == nil {
		if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetSecurebits, secbitsLockedNoRoot, 0, 0, 0, 0); errno != 0 {
			err = errno
		}
	}
	if err == nil {
		hdr := capHeader{version: linuxCapVer3}
		var data [2]capData
		if _, _, errno := syscall.Syscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
			err = errno
		}
	}
	if err == nil && !probeOnly {
		err = syscall.Chdir(cwd)
	}
	if err == nil && noNetwork {
		if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
			return errno
		}
		filter := [9]syscall.SockFilter{
			{Code: 0x20, K: 4},
			{Code: 0x15, Jt: 1, Jf: 0, K: arch},
			{Code: 0x06, K: 0x80000000},
			{Code: 0x20, K: 0},
			{Code: 0x15, Jt: 2, Jf: 0, K: sysSocket},
			{Code: 0x15, Jt: 1, Jf: 0, K: sysConnect},
			{Code: 0x15, Jt: 0, Jf: 1, K: sysBind},
			{Code: 0x06, K: 0x00050000 | uint32(syscall.EPERM)},
			{Code: 0x06, K: 0x7fff0000},
		}
		prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog)), 0, 0, 0); errno != 0 {
			return errno
		}
	}
	return err
}
