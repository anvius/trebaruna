//go:build windows

package fakecmd

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// job is the job object the stand-in runs in. It is kept until the stand-in
// exits: when the process goes, its last handle to the job goes with it.
var job windows.Handle

// confine puts the stand-in in a job object that ends every process in it when
// the job is closed. A test kills the stand-in the way it kills trebaruna, but
// the script's shell and its children would otherwise outlive it, holding the
// pipes the test reads to the end.
func confine() error {
	handle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(handle, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}
	if err := windows.AssignProcessToJobObject(handle, windows.CurrentProcess()); err != nil {
		return err
	}
	job = handle
	return nil
}
