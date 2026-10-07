package auth

import (
	"bufio"
	"bytes"
	"net"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/cyverse/sftpgo-auth-irods/commons"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func checkAuthorizedKey(authorizedKeys []byte, userKey ssh.PublicKey) (bool, []string, error) {
	authorizedKeysReader := bytes.NewReader(authorizedKeys)
	authorizedKeysScanner := bufio.NewScanner(authorizedKeysReader)

	for authorizedKeysScanner.Scan() {
		authorizedKeyLine := strings.TrimSpace(authorizedKeysScanner.Text())
		if authorizedKeyLine == "" || authorizedKeyLine[0] == '#' {
			// skip
			continue
		}

		authorizedKey, _, options, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyLine))
		if err != nil {
			// skip invalid public key
			log.WithError(err).Debugf("failed to parse a authorized key line")
			continue
		}

		if bytes.Equal(authorizedKey.Marshal(), userKey.Marshal()) {
			// found
			return true, options, nil
		}
	}

	if err := authorizedKeysScanner.Err(); err != nil {
		// a line longer than the scanner's buffer ends the scan early, which
		// would otherwise be reported as the key not being listed while the
		// keys after that line were never read
		return false, nil, errors.Wrap(err, "failed to read authorized_keys")
	}

	return false, nil, nil
}

// parseExpiryTime parses the value of an expiry-time option. OpenSSH accepts
// "YYYYMMDD[Z]" and "YYYYMMDDHHMM[SS][Z]", where a trailing 'Z' means the time
// is in UTC and its absence means it is in the local time zone.
func parseExpiryTime(timespec string) (time.Time, error) {
	location := time.Local
	if last := len(timespec) - 1; last >= 0 && (timespec[last] == 'Z' || timespec[last] == 'z') {
		location = time.UTC
		timespec = timespec[:last]
	}

	switch len(timespec) {
	case 8:
		// "YYYYMMDD" format
		return time.ParseInLocation("20060102", timespec, location)
	case 12:
		// "YYYYMMDDHHMM" format
		return time.ParseInLocation("200601021504", timespec, location)
	case 14:
		// "YYYYMMDDHHMMSS" format
		return time.ParseInLocation("20060102150405", timespec, location)
	default:
		return time.ParseInLocation("2006-01-02 15:04:05", timespec, location)
	}
}

func IsKeyExpired(options []string) bool {
	for _, option := range options {
		optKV := strings.SplitN(option, "=", 2)
		if len(optKV) == 2 {
			optK := strings.TrimSpace(optKV[0])
			if strings.ToLower(optK) == "expiry-time" {
				optV := strings.TrimSpace(optKV[1])
				optV = strings.Trim(optV, "\"")

				expiryDate, err := parseExpiryTime(optV)
				if err != nil {
					log.Debugf("failed to parse expiry date %q", optV)
					return true
				}

				nowTime := time.Now()
				log.Debugf("nowTime: %v, expiryDate: %v", nowTime, expiryDate)
				return nowTime.After(expiryDate)
			}
		}
	}
	// if nothing is specified, not expired
	return false
}

func IsClientRejected(clientIP string, options []string) bool {
	for _, option := range options {
		optKV := strings.SplitN(option, "=", 2)
		if len(optKV) == 2 {
			optK := strings.TrimSpace(optKV[0])
			if strings.ToLower(optK) == "from" {
				optV := strings.TrimSpace(optKV[1])
				optV = strings.Trim(optV, "\"")

				// comma separated strings
				ipFilters := strings.Split(optV, ",")
				if len(ipFilters) == 0 {
					// all allowed
					return false
				}

				rejected := true
				for _, ipFilter := range ipFilters {
					ipFilter = strings.TrimSpace(ipFilter)
					if len(ipFilter) > 0 {
						if ipFilter[0] == '!' {
							// negated - check rejected
							if matchIP(clientIP, ipFilter[1:]) {
								// reject if it matches
								log.Debugf("client %q is rejected because it matches to %q", clientIP, ipFilter)
								return true
							}
						} else {
							// check accepted
							if matchIP(clientIP, ipFilter) {
								rejected = false
							}
						}
					}
				}

				return rejected
			}
		}
	}
	// if nothing is specified, client is not rejected
	return false
}

func matchIP(clientIP string, filter string) bool {
	if strings.Index(filter, "/") > 0 {
		// filter is a mask
		// 1.2.3.4/32 pattern
		_, filterIPNet, err := net.ParseCIDR(filter)
		if err != nil {
			return false
		}

		ip := net.ParseIP(clientIP)
		return filterIPNet.Contains(ip)
	}

	// filter is an IP address containing ? or *
	filterRegexp := wildCardToRegexp(filter)
	matched, err := regexp.MatchString(filterRegexp, clientIP)
	if err != nil {
		return false
	}

	return matched
}

// wildCardToRegexp converts a wildcard pattern to a regular expression pattern.
// The pattern is anchored to match the whole input, and '?' matches exactly one
// character, as in OpenSSH's pattern matching.
func wildCardToRegexp(pattern string) string {
	var regexString strings.Builder

	regexString.WriteString("^")
	for _, c := range pattern {
		switch c {
		case '*':
			regexString.WriteString(".*")
		case '?':
			regexString.WriteString(".")
		default:
			regexString.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	regexString.WriteString("$")

	return regexString.String()
}

// GetHomeCollectionPath returns the home collection path a key is confined to,
// which is the user's home unless a home= option names another collection. The
// caller compares the result against commons.Config.GetHomeDirPath, so the
// default has to come from there rather than be spelled out again here.
func GetHomeCollectionPath(config *commons.Config, options []string) string {
	userHome := config.GetHomeDirPath()

	for _, option := range options {
		optKV := strings.SplitN(option, "=", 2)
		if len(optKV) == 2 {
			optK := strings.TrimSpace(optKV[0])
			if strings.ToLower(optK) == "home" {
				optV := strings.TrimSpace(optKV[1])
				optV = strings.TrimSpace(strings.Trim(optV, "\""))

				if len(optV) == 0 {
					// no path given, fall back to the default home
					log.Debugf("ignoring empty home option %q", option)
					continue
				}

				if optV[0] == '/' {
					// absolute. Clean it so that a path spelled differently
					// from the default home, such as a trailing slash, is not
					// mistaken for a custom one by the caller
					return path.Clean(optV)
				}
				return path.Join(userHome, optV)
			}
		}
	}
	return userHome
}
