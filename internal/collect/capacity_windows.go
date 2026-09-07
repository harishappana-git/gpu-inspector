//go:build windows

package collect

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/harishappana/gpu-inspector/internal/model"
	"golang.org/x/sys/windows"
)

func winFilesystemError(err error, message string) field {
	status := model.ToolError
	if errors.Is(err, os.ErrNotExist) {
		status = model.Unsupported
	}
	if errors.Is(err, os.ErrPermission) {
		status = model.PermissionDenied
	}
	return absent(status, message)
}

func workspaceUTF16(workspace string) (*uint16, error) {
	if workspace == "" {
		workspace = "."
	}
	absolute, err := filepath.Abs(workspace)
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	return windows.UTF16PtrFromString(absolute)
}

func capacityObservations(opts Options, start time.Time) []model.Observation {
	p, err := workspaceUTF16(opts.Workspace)
	var total, available, free uint64
	if err == nil {
		err = windows.GetDiskFreeSpaceEx(p, &available, &total, &free)
	}
	f := field{Status: model.Pass, Value: map[string]uint64{"total": total, "available_unprivileged": available, "free": free}, Unit: "bytes", Message: "Read-only Windows workspace capacity. Total and available values can reflect user quotas; availability can change before allocation."}
	if err != nil {
		f = winFilesystemError(err, "Workspace capacity unavailable.")
	}
	return []model.Observation{winHostObs("F01", "workspace_capacity", f, start)}
}

func windowsMountContext(workspace string, start time.Time) model.Observation {
	p, err := workspaceUTF16(workspace)
	var root [32768]uint16
	if err == nil {
		err = windows.GetVolumePathName(p, &root[0], uint32(len(root)))
	}
	var fs [128]uint16
	var flags uint32
	if err == nil {
		err = windows.GetVolumeInformation(&root[0], nil, 0, nil, nil, &flags, &fs[0], uint32(len(fs)))
	}
	if err != nil {
		return winHostObs("F02", "workspace_mount_context", winFilesystemError(err, "Workspace volume context unavailable; persistence remains undeclared."), start)
	}
	return winHostObs("F02", "workspace_mount_context", field{Status: model.Pass, Value: map[string]any{"filesystem_type": windows.UTF16ToString(fs[:]), "supports_file_acls": flags&windows.FILE_PERSISTENT_ACLS != 0, "read_only": flags&windows.FILE_READ_ONLY_VOLUME != 0, "persistence": "unknown; requires provider or user declaration"}, Message: "Workspace filesystem capabilities only; volume name, serial number and path are omitted. Local filesystem type does not establish storage persistence."}, start)
}
