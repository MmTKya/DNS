package hostinfo

import "golang.org/x/sys/unix"

// statFS measures a filesystem.
//
// Free space is the unprivileged figure, not the absolute one: a filesystem
// keeps a reserve only root may use, and reporting that as free is how a
// service runs out of disk on a card the panel said had room left.
func statFS(path string) (totalBytes, freeBytes int64, err error) {
	var fs unix.Statfs_t
	if err = unix.Statfs(path, &fs); err != nil {
		return 0, 0, err
	}

	size := int64(fs.Bsize)

	return int64(fs.Blocks) * size, int64(fs.Bavail) * size, nil
}
