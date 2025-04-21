//go:build !windows
// +build !windows

package sniff

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// mmapFile reads a file using memory mapping instead of ReadFile
// This reduces syscall overhead by avoiding extra copies
// Returns (data, isMapped, error) where isMapped indicates if unmapFile needs to be called
func mmapFile(path string) ([]byte, bool, error) {
	// Get file stats first
	fi, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}

	// Skip if not a regular file
	if !fi.Mode().IsRegular() {
		return nil, false, errors.New("not a regular file")
	}

	// Get file size
	size := fi.Size()
	if size == 0 {
		return []byte{}, false, nil
	}

	// Use ReadFile for small files (faster than mmap for small files)
	if size < 16*1024 {
		data, err := os.ReadFile(path)
		return data, false, err // Not memory mapped
	}

	// For larger files, use memory mapping
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Printf("failed to close file: %v", err)
		}
	}()

	// Memory map the file
	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, false, err
	}

	return data, true, nil
}

// unmapFile releases the memory-mapped file data
func unmapFile(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return syscall.Munmap(data)
}
