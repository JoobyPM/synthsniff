//go:build windows
// +build windows

package sniff

import (
	"errors"
	"os"
	"reflect"
	"syscall"
	"unsafe"
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
	// Convert to syscall handle
	handle, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, false, err
	}
	defer syscall.Close(handle)

	// Create file mapping
	mapHandle, err := syscall.CreateFileMapping(handle, nil, syscall.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return nil, false, err
	}
	defer syscall.CloseHandle(mapHandle)

	// Map view of file
	addr, err := syscall.MapViewOfFile(mapHandle, syscall.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return nil, false, err
	}

	// Create a slice that maps to the memory
	var data []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	hdr.Data = addr
	hdr.Len = int(size)
	hdr.Cap = hdr.Len

	return data, true, nil
}

// unmapFile releases the memory-mapped file data
func unmapFile(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	ptr := unsafe.Pointer(&data[0])
	return syscall.UnmapViewOfFile(uintptr(ptr))
}
