package cfg

import (
	"fmt"
	"os"
	"path/filepath"
)

// setLogFilePermissions sets the permissions of the log file to 0600.
// If the file does not exist, it will be created.
// lumberjack will then respect our permissions.
// https://github.com/natefinch/lumberjack/issues/82
func setLogFilePermissions(logDir string, logFile string) (string, error) {
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create log directory: %w", err)
	}

	logPath := filepath.Join(logDir, logFile)

	st, err := os.Stat(logPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("failed to check file existence: %w", err)
		}
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return "", fmt.Errorf("failed to create file: %w", err)
		}
		file.Close()
		return logPath, nil
	}

	if st.IsDir() {
		return "", fmt.Errorf("expected a file, found a directory: %s", logPath)
	}

	err = os.Chmod(logPath, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to change file permissions: %w", err)
	}

	return logPath, nil
}
