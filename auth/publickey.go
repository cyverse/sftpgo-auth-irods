package auth

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/cyverse/sftpgo-auth-irods/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func checkAuthorizedKey(authorizedKeys []byte, userKey ssh.PublicKey) (bool, []string) {
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
			log.Debugf("failed to parse a authorized key line - %s", err.Error())
			continue
		}

		if bytes.Equal(authorizedKey.Marshal(), userKey.Marshal()) {
			// found
			return true, options
		}
	}

	return false, nil
}

func IsKeyExpired(options []string) bool {
	for _, option := range options {
		optKV := strings.Split(option, "=")
		if len(optKV) == 2 {
			optK := strings.TrimSpace(optKV[0])
			if strings.ToLower(optK) == "expiry-time" {
				optV := strings.TrimSpace(optKV[1])
				optV = strings.Trim(optV, "\"")

				var expiryDate time.Time
				if len(optV) == 8 {
					// "YYYYMMDD" format
					d, err := time.ParseInLocation("20060102", optV, time.Local)
					if err != nil {
						log.Debugf("failed to parse expiry date '%s'", optV)
						return true
					}
					expiryDate = d
				} else if len(optV) == 12 {
					// "YYYYMMDDHHMM" format
					d, err := time.ParseInLocation("200601021504", optV, time.Local)
					if err != nil {
						log.Debugf("failed to parse expiry date '%s'", optV)
						return true
					}
					expiryDate = d
				} else if len(optV) == 14 {
					// "YYYYMMDDHHMMSS" format
					d, err := time.ParseInLocation("20060102150405", optV, time.Local)
					if err != nil {
						log.Debugf("failed to parse expiry date '%s'", optV)
						return true
					}
					expiryDate = d
				} else {
					d, err := time.ParseInLocation("2006-01-02 15:04:05", optV, time.Local)
					if err != nil {
						log.Debugf("failed to parse expiry date '%s'", optV)
						return true
					}
					expiryDate = d
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
		optKV := strings.Split(option, "=")
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
								log.Debugf("client %s is rejected because it matches to %s", clientIP, ipFilter)
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
func wildCardToRegexp(pattern string) string {
	regexString := ""
	for _, c := range pattern {
		if c == '*' {
			regexString += ".*"
		} else if c == '?' {
			regexString += ".?"
		} else {
			regexString += regexp.QuoteMeta(string(c))
		}
	}

	return regexString
}

// GetHomeCollectionPath returns home collection path
func GetHomeCollectionPath(config *types.Config, options []string) string {
	userHome := fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername)

	for _, option := range options {
		optKV := strings.Split(option, "=")
		if len(optKV) == 2 {
			optK := strings.TrimSpace(optKV[0])
			if strings.ToLower(optK) == "home" {
				optV := strings.TrimSpace(optKV[1])
				optV = strings.Trim(optV, "\"")

				return path.Join(userHome, optV)
			}
		}
	}
	return userHome
}
