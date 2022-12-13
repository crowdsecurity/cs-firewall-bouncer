package version

import (
	"fmt"
	"log"
	"runtime"
)

/*

Given a version number MAJOR.MINOR.PATCH, increment the:

	MAJOR version when you make incompatible API changes,
	MINOR version when you add functionality in a backwards compatible manner, and
	PATCH version when you make backwards compatible bug fixes.

Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format.

*/

var (
	Version   string                  // = "v0.0.0"
	BuildDate string                  // = "I don't remember exactly"
	Tag       string                  // = "dev"
	GoVersion = runtime.Version()[2:] // = "1.13"
)

func ShowStr() string {
	ret := ""
	ret += fmt.Sprintf("version: %s-%s\n", Version, Tag)
	ret += fmt.Sprintf("BuildDate: %s\n", BuildDate)
	ret += fmt.Sprintf("GoVersion: %s\n", GoVersion)
	return ret
}

func Show() {
	log.Printf("version: %s-%s", Version, Tag)
	log.Printf("BuildDate: %s", BuildDate)
	log.Printf("GoVersion: %s", GoVersion)
}

func VersionStr() string {
	return fmt.Sprintf("%s-%s", Version, Tag)
}
