//go:build linux

package admission

import "golang.org/x/sys/unix"

func platformOpenAtNoFollow(dirFD int, name string, flags int, mode uint32, noCrossDevice bool) (int, error) {
	resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS)
	if noCrossDevice {
		resolve |= unix.RESOLVE_NO_XDEV
	}
	return unix.Openat2(dirFD, name, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Mode:    uint64(mode),
		Resolve: resolve,
	})
}

func platformRenameNoReplace(oldDirFD int, oldName string, newDirFD int, newName string) error {
	return unix.Renameat2(oldDirFD, oldName, newDirFD, newName, unix.RENAME_NOREPLACE)
}

func platformStatSnapshotStable(before unix.Stat_t, after unix.Stat_t) bool {
	return before.Dev == after.Dev &&
		before.Ino == after.Ino &&
		before.Mode == after.Mode &&
		before.Nlink == after.Nlink &&
		before.Size == after.Size &&
		before.Mtim.Sec == after.Mtim.Sec &&
		before.Mtim.Nsec == after.Mtim.Nsec &&
		before.Ctim.Sec == after.Ctim.Sec &&
		before.Ctim.Nsec == after.Ctim.Nsec
}
