// package main....
package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// WriteFile writes a file automically.
//
// From: https://lwn.net/Articles/457667/
//
// 1. create a new temp file (on the same file system!)
// 2. write data to the temp file
// 3. fsync() the temp file
// 4. rename the temp file to the appropriate name
// 5. fsync() the containing directory
//
// The fsyncs probably aren't necessary on COS since we'll probably be writing
// to tmpfs (or overlayfs on tmpfs), but they should be close to a noop and
// quick, so we can be over paranoid.
func writeFile(path string, data []byte) error {
	return writeFileAtomic(path+".tmp", path, data)
}

// writeFileSync writes a file synchronously. It's broken out of
// writeFileAtomic because we want to catch all errors and the a function block
// simplifies error handling in this section.
func writeFileSync(path string, data []byte) (_err error) {
	// Step 1
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); _err == nil {
			_err = err
		}
		if _err != nil {
			os.Remove(path)
		}
	}()

	// Step 2
	var n int
	n, err = f.Write(data)
	if err != nil {
		return err
	}
	if n < len(data) {
		return io.ErrShortWrite
	}

	// Step 3
	return f.Sync()
}

func writeFileAtomic(tempPath, path string, data []byte) (_err error) {
	if err := writeFileSync(tempPath, data); err != nil {
		return err
	}

	// Step 4
	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath)
		return err
	}

	// Step 5
	dir, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer func() {
		if err := dir.Close(); _err == nil {
			_err = err
		}
	}()
	return dir.Sync()
}
