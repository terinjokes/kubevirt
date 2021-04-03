package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"syscall"

	"github.com/opencontainers/selinux/go-selinux"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// NewGetEnforceCommand determines if selinux is enabled in the kernel (enforced or permissive)
func NewGetEnforceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "getenforce",
		Short: "determine if selinux is present",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			mntPoint, err := findSELinuxMountpoint()
			if err != nil {
				fmt.Println("disabled")
				return nil
			}

			enabled, err := isSELinuxEnabled()
			if err != nil || !enabled {
				fmt.Println("disabled")
				return nil
			}

			enforcing, err := isSELinuxEnforcing(mntPoint)
			if err != nil {
				fmt.Println("disabled")
				return nil
			}

			if !enforcing {
				fmt.Println("permissive")
				return nil
			}

			fmt.Println("enforcing")
			return nil
		},
	}
	return cmd
}

func RelabelCommand() *cobra.Command {
	return &cobra.Command{
		Use:       "relabel",
		Short:     "relabel a file with the given selinux label, if the path is not labeled like this already",
		Example:   "virt-chroot selinux relabel <new-label> <file-path>",
		ValidArgs: nil,
		Args:      cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			label := args[0]
			filePath := args[1]

			currentFileLabel, err := selinux.FileLabel(filePath)
			if err != nil {
				return fmt.Errorf("could not retrieve label of file %s. Reason: %v", filePath, err)
			}

			if currentFileLabel != label {
				if err := selinux.Chcon(filePath, label, false); err != nil {
					return fmt.Errorf("error relabeling file %s with label %s. Reason: %v", filePath, label, err)
				}
			}

			return nil
		},
	}
}

// findSELinuxMountpoint searches known paths for an SELinux mount.
// returns the path for the first mountpoint of the SELinux type.
func findSELinuxMountpoint() (string, error) {
	paths := []string{
		"/sys/fs/selinux", // modern mount location
		"/selinux",        // legacy mount location, still checked by getenforce
	}

	for _, p := range paths {
		var fi unix.Statfs_t
		err := statfs(p, &fi)

		if err != nil && !errors.Is(err, syscall.ENOENT) {
			return "", err
		}

		if uint32(fi.Type) == uint32(unix.SELINUX_MAGIC) {
			return p, nil
		}
	}

	return "", os.ErrNotExist
}

// statfs is a wrapper of unix.Statfs that retries after
// being interrupted by signals.
func statfs(path string, buf *unix.Statfs_t) error {
	for {
		err := unix.Statfs(path, buf)
		if err == nil {
			return nil
		}

		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}

		return err
	}
}

// isSELinuxEnabled determines if there is SELinux configuration
// at the well-known location.
func isSELinuxEnabled() (bool, error) {
	_, err := os.Lstat("/etc/selinux/config")
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// isSELinuxEnforcing checks the state of SELinux at the provided mountpoint.
func isSELinuxEnforcing(mntPoint string) (bool, error) {
	enforcing, err := ioutil.ReadFile(path.Join(mntPoint, "enforce"))
	switch {
	case err != nil:
		return false, err
	case bytes.Compare(enforcing, []byte("1")) == 0:
		return true, nil
	default:
		return false, nil
	}
}
