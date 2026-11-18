//go:build darwin

package admission

import "golang.org/x/sys/unix"

func platformOpenAtNoFollow(dirFD int, name string, flags int, mode uint32, _ bool) (int, error) {
	return unix.Openat(dirFD, name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW_ANY, mode)
}

func platformRenameNoReplace(oldDirFD int, oldName string, newDirFD int, newName string) error {
	return unix.RenameatxNp(oldDirFD, oldName, newDirFD, newName, unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY)
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
