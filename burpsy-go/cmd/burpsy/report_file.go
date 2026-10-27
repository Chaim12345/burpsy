package main

import "os"

// writeReport writes a report the CLI was asked to save (-out). Reports carry findings with their
// evidence — requests, responses, cookies — so they are created owner-only, like the project file
// and capture segments (burpsy-react-ui-other-writers-perms). An existing file keeps its owner but
// is tightened too: os.WriteFile alone never changes the mode of a file it truncates.
func writeReport(path string, doc []byte) error {
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
