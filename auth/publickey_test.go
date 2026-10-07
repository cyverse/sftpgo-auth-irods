package auth

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/cyverse/sftpgo-auth-irods/commons"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// These are real keys, so ssh.ParseAuthorizedKey accepts them. Nothing here
// contacts an iRODS server: every function under test works on the
// authorized_keys text alone.
const (
	keyA   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8o70dSw02wiirDTdUbAs2tLnhXyeGSfMRBR8nhSGWX key-a@example.com"
	keyB   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPAswsL8/TmpDS7llVqNN2LOvFolO+0CLxxLzfgL0HKP key-b@example.com"
	keyRSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZ7Ed4qRoJ7TFV6CtS4Hx3A827B5wWI2bbfyLbhqmWuF4TkzUjvLfJ3Ch30ACYBhJUWavvnsywZMufwUnDfrtNo2ZMEwgBk4LbAdE5D5P9aV4dmQzd/9q9sWINJknRYFfBa/IMkTtNGN+q6kR4g/NHBOGTjyC+QkWjSeVLzBVzTs9axY6qwkwcYjJ0JwqHxaXJ+Jst1iWR2JX5FLdmbhenB/M4VwUkvm0NVsk7BMBtYRCOTjPAUvpjjy9NHvpchINjC7/zfjVU/Yq4qwp/SVaqOfRHTGECRDq+vJNxuqbk2aBzva8UhHLNbtg1uiHgIHoj3MflFJxqgnyJpDWrvwxZ key-rsa@example.com"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func mustParseKey(t *testing.T, authorizedKey string) ssh.PublicKey {
	t.Helper()

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		t.Fatalf("failed to parse the test key: %v", err)
	}
	return key
}

func testConfig() *commons.Config {
	return &commons.Config{
		IRODSZone:           "testZone",
		SFTPGoAuthdUsername: "testuser",
	}
}

const testUserHome = "/testZone/home/testuser"

// TestCheckAuthorizedKey covers matching a key against an authorized_keys file
// and returning that line's options.
func TestCheckAuthorizedKey(t *testing.T) {
	tests := []struct {
		name           string
		authorizedKeys string
		userKey        string
		wantFound      bool
		wantOptions    []string
	}{
		{
			name:           "single matching key",
			authorizedKeys: keyA,
			userKey:        keyA,
			wantFound:      true,
		},
		{
			name:           "key not listed",
			authorizedKeys: keyA,
			userKey:        keyB,
			wantFound:      false,
		},
		{
			name:           "empty file",
			authorizedKeys: "",
			userKey:        keyA,
			wantFound:      false,
		},
		{
			name:           "matches the second line",
			authorizedKeys: keyA + "\n" + keyB,
			userKey:        keyB,
			wantFound:      true,
		},
		{
			name:           "skips comments and blank lines",
			authorizedKeys: "# a comment\n\n   \n" + keyB,
			userKey:        keyB,
			wantFound:      true,
		},
		{
			name:           "skips unparseable lines",
			authorizedKeys: "not a key at all\nssh-ed25519 !!!notbase64!!!\n" + keyB,
			userKey:        keyB,
			wantFound:      true,
		},
		{
			name:           "returns the options of the matching line only",
			authorizedKeys: `from="10.0.0.1" ` + keyA + "\n" + `home="projB" ` + keyB,
			userKey:        keyB,
			wantFound:      true,
			wantOptions:    []string{`home="projB"`},
		},
		{
			name:           "handles CRLF line endings",
			authorizedKeys: keyA + "\r\n" + keyB + "\r\n",
			userKey:        keyB,
			wantFound:      true,
		},
		{
			name:           "matches a key of a different type",
			authorizedKeys: keyA + "\n" + keyRSA,
			userKey:        keyRSA,
			wantFound:      true,
		},
		{
			name:           "multiple options are all returned",
			authorizedKeys: `from="10.0.0.1",expiry-time="20301231" ` + keyA,
			userKey:        keyA,
			wantFound:      true,
			wantOptions:    []string{`from="10.0.0.1"`, `expiry-time="20301231"`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			found, options := checkAuthorizedKey([]byte(test.authorizedKeys), mustParseKey(t, test.userKey))

			if found != test.wantFound {
				t.Fatalf("found = %v, want %v", found, test.wantFound)
			}
			if !equalStrings(options, test.wantOptions) {
				t.Errorf("options = %v, want %v", options, test.wantOptions)
			}
		})
	}
}

// TestParseExpiryTime covers every timespec OpenSSH accepts, including the
// trailing Z that selects UTC.
func TestParseExpiryTime(t *testing.T) {
	tests := []struct {
		name     string
		timespec string
		want     time.Time
		wantErr  bool
	}{
		{
			name:     "YYYYMMDD",
			timespec: "20301231",
			want:     time.Date(2030, 12, 31, 0, 0, 0, 0, time.Local),
		},
		{
			name:     "YYYYMMDD with Z",
			timespec: "20301231Z",
			want:     time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "YYYYMMDDHHMM",
			timespec: "203012312359",
			want:     time.Date(2030, 12, 31, 23, 59, 0, 0, time.Local),
		},
		{
			name:     "YYYYMMDDHHMM with Z",
			timespec: "203012312359Z",
			want:     time.Date(2030, 12, 31, 23, 59, 0, 0, time.UTC),
		},
		{
			name:     "YYYYMMDDHHMMSS",
			timespec: "20301231235959",
			want:     time.Date(2030, 12, 31, 23, 59, 59, 0, time.Local),
		},
		{
			name:     "YYYYMMDDHHMMSS with Z",
			timespec: "20301231235959Z",
			want:     time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			name:     "lower case z also means UTC",
			timespec: "20301231z",
			want:     time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "the extension format is still accepted",
			timespec: "2030-12-31 23:59:59",
			want:     time.Date(2030, 12, 31, 23, 59, 59, 0, time.Local),
		},
		{name: "empty", timespec: "", wantErr: true},
		{name: "not a date", timespec: "garbage", wantErr: true},
		{name: "impossible date", timespec: "99999999", wantErr: true},
		{name: "month out of range", timespec: "20301331", wantErr: true},
		{name: "wrong length", timespec: "2030123", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseExpiryTime(test.timespec)

			if test.wantErr {
				if err == nil {
					t.Fatalf("parseExpiryTime(%q) = %v, want an error", test.timespec, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseExpiryTime(%q) failed: %v", test.timespec, err)
			}
			if !got.Equal(test.want) {
				t.Errorf("parseExpiryTime(%q) = %v, want %v", test.timespec, got, test.want)
			}
		})
	}
}

// TestParseExpiryTimeZSelectsUTC checks that the Z suffix shifts the instant by
// the local zone's offset. On a machine running in UTC the offset is zero and
// the two parses coincide, which is still the correct result.
func TestParseExpiryTimeZSelectsUTC(t *testing.T) {
	local, err := parseExpiryTime("20301231235959")
	if err != nil {
		t.Fatalf("failed to parse the local timespec: %v", err)
	}

	utc, err := parseExpiryTime("20301231235959Z")
	if err != nil {
		t.Fatalf("failed to parse the UTC timespec: %v", err)
	}

	_, offset := local.Zone()
	want := time.Duration(offset) * time.Second
	if got := utc.Sub(local); got != want {
		t.Errorf("the Z suffix shifted the instant by %v, want %v for zone offset %ds", got, want, offset)
	}
}

// TestIsKeyExpired covers the expiry-time option as a whole, including the
// fail-closed behaviour on a value that cannot be parsed.
func TestIsKeyExpired(t *testing.T) {
	tests := []struct {
		name    string
		options []string
		want    bool
	}{
		{name: "no options", options: nil, want: false},
		{name: "unrelated options only", options: []string{"no-pty", `from="10.0.0.1"`}, want: false},
		{name: "future date", options: []string{`expiry-time="20301231"`}, want: false},
		{name: "past date", options: []string{`expiry-time="20200101"`}, want: true},
		{name: "future date in UTC", options: []string{`expiry-time="20301231Z"`}, want: false},
		{name: "past date in UTC", options: []string{`expiry-time="20200101Z"`}, want: true},
		{name: "future timestamp", options: []string{`expiry-time="20301231235959"`}, want: false},
		{name: "past timestamp", options: []string{`expiry-time="20200101000000"`}, want: true},
		{name: "unquoted value", options: []string{`expiry-time=20301231`}, want: false},
		{name: "extension format in the future", options: []string{`expiry-time="2030-12-31 23:59:59"`}, want: false},
		{name: "unparseable value fails closed", options: []string{`expiry-time="garbage"`}, want: true},
		{name: "empty value fails closed", options: []string{`expiry-time=""`}, want: true},
		{
			// a value containing '=' must not make the option disappear
			name:    "value with an equals sign fails closed",
			options: []string{`expiry-time="20200101=bad"`},
			want:    true,
		},
		{
			name:    "found among other options",
			options: []string{"no-pty", `environment="FOO=bar"`, `expiry-time="20200101"`},
			want:    true,
		},
		{
			name:    "case insensitive key",
			options: []string{`Expiry-Time="20200101"`},
			want:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsKeyExpired(test.options); got != test.want {
				t.Errorf("IsKeyExpired(%v) = %v, want %v", test.options, got, test.want)
			}
		})
	}
}

// TestIsClientRejected covers the from option. A pattern has to match the whole
// address, so a listed address must not admit a client whose address merely
// contains it.
func TestIsClientRejected(t *testing.T) {
	tests := []struct {
		name     string
		option   string
		clientIP string
		want     bool
	}{
		{name: "no from option", option: "no-pty", clientIP: "10.0.0.1", want: false},
		{name: "exact match", option: `from="10.0.0.1"`, clientIP: "10.0.0.1", want: false},
		{
			name:     "client address contains the pattern as a prefix",
			option:   `from="10.0.0.1"`,
			clientIP: "10.0.0.199",
			want:     true,
		},
		{
			name:     "client address contains the pattern as a suffix",
			option:   `from="10.0.0.1"`,
			clientIP: "110.0.0.1",
			want:     true,
		},
		{
			name:     "client address contains the pattern in the middle",
			option:   `from="10.0.0.1"`,
			clientIP: "110.0.0.199",
			want:     true,
		},
		{name: "star matches a whole octet", option: `from="10.0.0.*"`, clientIP: "10.0.0.55", want: false},
		{name: "star does not cross the pattern start", option: `from="10.0.0.*"`, clientIP: "110.0.0.55", want: true},
		{name: "star alone matches anything", option: `from="*"`, clientIP: "203.0.113.9", want: false},
		{name: "question mark matches one character", option: `from="10.0.0.?"`, clientIP: "10.0.0.5", want: false},
		{name: "question mark does not match two", option: `from="10.0.0.?"`, clientIP: "10.0.0.55", want: true},
		{name: "question mark does not match zero", option: `from="10.0.0.?"`, clientIP: "10.0.0.", want: true},
		{name: "inside the CIDR", option: `from="10.0.0.0/24"`, clientIP: "10.0.0.7", want: false},
		{name: "outside the CIDR", option: `from="10.0.0.0/24"`, clientIP: "10.0.1.7", want: true},
		{name: "single host CIDR", option: `from="10.0.0.7/32"`, clientIP: "10.0.0.7", want: false},
		{name: "comma separated list, second entry", option: `from="1.2.3.4,5.6.7.8"`, clientIP: "5.6.7.8", want: false},
		{name: "comma separated list, no entry matches", option: `from="1.2.3.4,5.6.7.8"`, clientIP: "5.6.7.80", want: true},
		{name: "negated entry is rejected", option: `from="!10.0.0.1,10.0.0.*"`, clientIP: "10.0.0.1", want: true},
		{name: "negated entry lets others through", option: `from="!10.0.0.1,10.0.0.*"`, clientIP: "10.0.0.2", want: false},
		{
			// the negated pattern must not match the whole address by accident
			name:     "negation does not catch a containing address",
			option:   `from="!10.0.0.1,110.0.0.10"`,
			clientIP: "110.0.0.10",
			want:     false,
		},
		{name: "only negations rejects everything", option: `from="!10.0.0.1"`, clientIP: "10.0.0.2", want: true},
		{name: "empty value rejects", option: `from=""`, clientIP: "10.0.0.1", want: true},
		{
			// a value containing '=' must not make the option disappear
			name:     "value with an equals sign still restricts",
			option:   `from="10.0.0.1,host=a"`,
			clientIP: "203.0.113.9",
			want:     true,
		},
		{name: "invalid client address never matches", option: `from="10.0.0.0/24"`, clientIP: "not-an-ip", want: true},
		{name: "case insensitive key", option: `From="10.0.0.1"`, clientIP: "10.0.0.1", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsClientRejected(test.clientIP, []string{test.option}); got != test.want {
				t.Errorf("IsClientRejected(%q, [%s]) = %v, want %v", test.clientIP, test.option, got, test.want)
			}
		})
	}
}

// TestIsClientRejectedIgnoresNoise checks that the from option is still found
// when other options surround it.
func TestIsClientRejectedIgnoresNoise(t *testing.T) {
	options := []string{"no-pty", "restrict", `command="ls -l"`, `environment="FOO=bar"`, `from="10.0.0.*"`}

	if IsClientRejected("10.0.0.5", options) {
		t.Error("a listed client was rejected")
	}
	if !IsClientRejected("203.0.113.9", options) {
		t.Error("an unlisted client was accepted")
	}
}

// TestWildCardToRegexp checks that the generated pattern is anchored, so that
// it matches the whole address rather than a substring.
func TestWildCardToRegexp(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{pattern: "10.0.0.1", want: `^10\.0\.0\.1$`},
		{pattern: "10.0.0.*", want: `^10\.0\.0\..*$`},
		{pattern: "10.0.0.?", want: `^10\.0\.0\..$`},
		{pattern: "*", want: "^.*$"},
		{pattern: "", want: "^$"},
	}

	for _, test := range tests {
		t.Run(test.pattern, func(t *testing.T) {
			if got := wildCardToRegexp(test.pattern); got != test.want {
				t.Errorf("wildCardToRegexp(%q) = %q, want %q", test.pattern, got, test.want)
			}
		})
	}
}

// TestMatchIP covers the two forms a from entry can take.
func TestMatchIP(t *testing.T) {
	tests := []struct {
		name     string
		clientIP string
		filter   string
		want     bool
	}{
		{name: "exact address", clientIP: "10.0.0.1", filter: "10.0.0.1", want: true},
		{name: "containing address is not a match", clientIP: "10.0.0.11", filter: "10.0.0.1", want: false},
		{name: "wildcard", clientIP: "10.0.0.11", filter: "10.0.0.*", want: true},
		{name: "CIDR member", clientIP: "10.0.0.11", filter: "10.0.0.0/24", want: true},
		{name: "CIDR non member", clientIP: "10.0.1.11", filter: "10.0.0.0/24", want: false},
		{name: "malformed CIDR", clientIP: "10.0.0.1", filter: "10.0.0.0/999", want: false},
		{name: "unparseable client address", clientIP: "not-an-ip", filter: "10.0.0.0/24", want: false},
		{name: "IPv6 in its own CIDR", clientIP: "2001:db8::1", filter: "2001:db8::/32", want: true},
		{name: "IPv6 outside the CIDR", clientIP: "2001:db9::1", filter: "2001:db8::/32", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := matchIP(test.clientIP, test.filter); got != test.want {
				t.Errorf("matchIP(%q, %q) = %v, want %v", test.clientIP, test.filter, got, test.want)
			}
		})
	}
}

// TestGetHomeCollectionPath covers the home option, which confines a key to a
// collection. A value that cannot be used must fall back to the default home
// rather than crash.
func TestGetHomeCollectionPath(t *testing.T) {
	tests := []struct {
		name    string
		options []string
		want    string
	}{
		{name: "no options", options: nil, want: testUserHome},
		{name: "unrelated options only", options: []string{"no-pty", `from="10.0.0.1"`}, want: testUserHome},
		{
			name:    "absolute path",
			options: []string{`home="/testZone/home/other/projA"`},
			want:    "/testZone/home/other/projA",
		},
		{
			name:    "relative path is resolved against the home",
			options: []string{`home="projA"`},
			want:    testUserHome + "/projA",
		},
		{
			// the caller compares the result with the default home, so a path
			// spelled differently must still normalize to it
			name:    "absolute path with a trailing slash",
			options: []string{`home="` + testUserHome + `/"`},
			want:    testUserHome,
		},
		{
			name:    "absolute path with a doubled slash",
			options: []string{`home="/` + testUserHome + `"`},
			want:    testUserHome,
		},
		{
			name:    "absolute path with a dot segment",
			options: []string{`home="` + testUserHome + `/."`},
			want:    testUserHome,
		},
		{
			name:    "absolute subcollection with a trailing slash",
			options: []string{`home="` + testUserHome + `/projA/"`},
			want:    testUserHome + "/projA",
		},
		{
			name:    "absolute subcollection with a dot segment",
			options: []string{`home="` + testUserHome + `/./projA"`},
			want:    testUserHome + "/projA",
		},
		{
			name:    "relative path with a trailing slash",
			options: []string{`home="projA/"`},
			want:    testUserHome + "/projA",
		},
		{
			name:    "nested relative path",
			options: []string{`home="sub/dir"`},
			want:    testUserHome + "/sub/dir",
		},
		{name: "unquoted value", options: []string{`home=projA`}, want: testUserHome + "/projA"},
		{name: "empty value falls back", options: []string{`home=""`}, want: testUserHome},
		{name: "missing value falls back", options: []string{`home=`}, want: testUserHome},
		{name: "blank value falls back", options: []string{`home="   "`}, want: testUserHome},
		{
			name:    "an empty value does not hide a later one",
			options: []string{`home=""`, `home="projB"`},
			want:    testUserHome + "/projB",
		},
		{
			// a value containing '=' must not make the option disappear, or the
			// key would silently get the whole home collection
			name:    "path containing an equals sign",
			options: []string{`home="/testZone/home/testuser/run=2024"`},
			want:    "/testZone/home/testuser/run=2024",
		},
		{
			name:    "relative path containing an equals sign",
			options: []string{`home="run=2024"`},
			want:    testUserHome + "/run=2024",
		},
		{
			name:    "found among other options",
			options: []string{"no-pty", `environment="FOO=bar"`, `home="projA"`},
			want:    testUserHome + "/projA",
		},
		{name: "case insensitive key", options: []string{`Home="projA"`}, want: testUserHome + "/projA"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := GetHomeCollectionPath(testConfig(), test.options); got != test.want {
				t.Errorf("GetHomeCollectionPath(%v) = %q, want %q", test.options, got, test.want)
			}
		})
	}
}

// TestGetHomeCollectionPathMatchesDefault checks that a home option naming the
// default collection is reported as the default, because the caller compares
// the two to decide whether the key needs its own SFTPGo user.
func TestGetHomeCollectionPathMatchesDefault(t *testing.T) {
	config := testConfig()

	// every spelling of the default home has to compare equal to it, otherwise
	// the key is given its own SFTPGo user and virtual folder for no reason
	options := []string{
		`home="` + testUserHome + `"`,
		`home="` + testUserHome + `/"`,
		`home="/` + testUserHome + `"`,
		`home="` + testUserHome + `/."`,
		`home="."`,
		`home=""`,
	}

	for _, option := range options {
		t.Run(option, func(t *testing.T) {
			got := GetHomeCollectionPath(config, []string{option})
			if got != config.GetHomeDirPath() {
				t.Errorf("GetHomeCollectionPath([%s]) = %q, want the default home %q",
					option, got, config.GetHomeDirPath())
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
