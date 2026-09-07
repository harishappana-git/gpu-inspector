//go:build windows

package processutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A suspended start closes the gap in which a process could create children
// before it is assigned to our job. No application code runs until assignment.
// Run requires a command created with exec.CommandContext, even when the
// caller uses context.Background, because it installs a cancellation handler.
func Run(cmd *exec.Cmd) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create child job: %w", err)
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_SUSPENDED}
	cmd.Cancel = func() error {
		// Kill the process as well: cancellation can race its job assignment.
		jobErr := windows.TerminateJobObject(job, 1)
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		processErr := cmd.Process.Kill()
		if jobErr == nil {
			return nil
		}
		return processErr
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	abort := func(cause error) error { _ = cmd.Process.Kill(); _ = cmd.Wait(); return cause }
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return abort(err)
	}
	err = windows.AssignProcessToJobObject(job, process)
	windows.CloseHandle(process)
	if err != nil {
		return abort(fmt.Errorf("assign child job: %w", err))
	}
	if err = resumeInitialThread(uint32(cmd.Process.Pid)); err != nil {
		return abort(err)
	}
	return cmd.Wait()
}

func resumeInitialThread(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		thread, openErr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if openErr != nil {
			return openErr
		}
		_, resumeErr := windows.ResumeThread(thread)
		windows.CloseHandle(thread)
		return resumeErr
	}
	return errors.New("suspended child initial thread unavailable")
}
