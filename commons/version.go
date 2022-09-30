package commons

import (
	"encoding/json"
	"fmt"
	"runtime"
)

var (
	releaseVersion string
	gitCommit      string
	buildDate      string
)

// VersionInfo object contains version related info
type VersionInfo struct {
	ReleaseVersion string `json:"releaseVersion"`
	GitCommit      string `json:"gitCommit"`
	BuildDate      string `json:"buildDate"`
	GoVersion      string `json:"goVersion"`
	Compiler       string `json:"compiler"`
	Platform       string `json:"platform"`
}

// GetVersion returns VersionInfo object
func GetVersion() VersionInfo {
	return VersionInfo{
		ReleaseVersion: releaseVersion,
		GitCommit:      gitCommit,
		BuildDate:      buildDate,
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
		Platform:       fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// GetReleaseVersion returns release version in string
func GetReleaseVersion() string {
	return releaseVersion
}

// GetVersionJSON returns VersionInfo object in JSON string
func GetVersionJSON() (string, error) {
	info := GetVersion()
	marshalled, err := json.MarshalIndent(&info, "", "  ")
	if err != nil {
		return "", err
	}
	return string(marshalled), nil
}
