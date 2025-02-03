package scanner

import (
	"log"
	"os"
	"regexp"

	"github.com/4lch3mis7/webzoro-golang/utils"
)

var (
	urlRegexp    = regexp.MustCompile(`^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|\/|\/\/)?[A-z0-9_-]*?[:]?[A-z0-9_-]*?[@]?[A-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$`)
	domainRegexp = regexp.MustCompile(`^[0-9A-Za-z\.\-]+$`)
	ipRegexp     = regexp.MustCompile(`^(?:\d+\.){3}\d+$`)
)

type Target struct {
	Target     string
	Subdomains []string
}

// Returns `true` if the Target is either an IP address or a domain name
func (t *Target) IsValidHost() bool {
	return t.IsIP() || t.IsDomain()
}

// Returns `true` if the Target is an IP address
func (t *Target) IsIP() bool {
	return ipRegexp.MatchString(t.Target)
}

// Returns `true` if the Target is a domain name
func (t *Target) IsDomain() bool {
	return domainRegexp.MatchString(t.Target) && !ipRegexp.MatchString(t.Target)
}

// Returns `true` if the Target is an URL
func (t *Target) IsUrl() bool {
	return !t.IsDomain() && !t.IsIP() && urlRegexp.MatchString(t.Target)
}

// Get working directory of the target. Creates a directory if not exists.
func (t *Target) GetWorkingDir() string {
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	dir := pwd + "/" + t.Target
	utils.CheckAndCreateDir(dir)
	return dir
}

// Returns URL of the target
func (t *Target) Url() string {
	if t.IsUrl() {
		return t.Target
	}
	return "http://" + t.Target
}
