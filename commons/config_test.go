package commons

import (
	"os"
	"reflect"
	"testing"
)

// authCacheTimeEnvVar is the variable ReadFromEnv reads the cache time from.
const authCacheTimeEnvVar = "SFTPGO_AUTH_CACHE_TIME"

// TestAuthCacheTimeTags checks the variable the field is read from, and that it
// carries no default tag: ReadFromEnv applies defaultAuthCacheTime itself, the
// same way it does for the other settings.
func TestAuthCacheTimeTags(t *testing.T) {
	field, ok := reflect.TypeOf(Config{}).FieldByName("SFTPGoAuthCacheTime")
	if !ok {
		t.Fatal("Config has no SFTPGoAuthCacheTime field")
	}

	if got := field.Tag.Get("envconfig"); got != authCacheTimeEnvVar {
		t.Errorf("the envconfig tag is %q, want %q", got, authCacheTimeEnvVar)
	}
	if got := field.Tag.Get("default"); got != "" {
		t.Errorf("the field carries default:%q, want the default applied in ReadFromEnv", got)
	}
}

// TestReadFromEnvAuthCacheTime covers the default and the explicit values. 0 is
// treated as unset, the same way the other numeric settings are, so the cache
// cannot be turned off through this variable.
func TestReadFromEnvAuthCacheTime(t *testing.T) {
	tests := []struct {
		name  string
		value string
		set   bool
		want  int64
	}{
		{name: "absent", want: defaultAuthCacheTime},
		{name: "zero falls back to the default", value: "0", set: true, want: defaultAuthCacheTime},
		{name: "shorter than the default", value: "60", set: true, want: 60},
		{name: "longer than the default", value: "3600", set: true, want: 3600},
		{name: "the default spelled out", value: "300", set: true, want: 300},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Setenv restores the original value on cleanup, so go through it
			// before unsetting rather than leaving the variable cleared
			t.Setenv(authCacheTimeEnvVar, test.value)
			if !test.set {
				if err := os.Unsetenv(authCacheTimeEnvVar); err != nil {
					t.Fatalf("failed to clear %s: %v", authCacheTimeEnvVar, err)
				}
			}

			config, err := ReadFromEnv()
			if err != nil {
				t.Fatalf("ReadFromEnv() failed: %v", err)
			}

			if config.SFTPGoAuthCacheTime != test.want {
				t.Errorf("auth cache time = %d, want %d", config.SFTPGoAuthCacheTime, test.want)
			}
		})
	}
}

// TestValidateAuthCacheTime checks that only a negative cache time is refused.
func TestValidateAuthCacheTime(t *testing.T) {
	tests := []struct {
		cacheTime int64
		wantErr   bool
	}{
		{cacheTime: -1, wantErr: true},
		{cacheTime: -300, wantErr: true},
		{cacheTime: 0},
		{cacheTime: 300},
	}

	for _, test := range tests {
		config := &Config{
			IRODSHost:           "irods.example.com",
			IRODSPort:           1247,
			IRODSZone:           "testZone",
			IRODSAuthScheme:     "native",
			SFTPGoAuthdUsername: "testuser",
			SFTPGoAuthdPassword: "test-user-password",
			SFTPGoAuthdIP:       "10.10.10.10",
			SFTPGoLogDir:        "/tmp",
			SFTPGoHomeDir:       "/srv/sftpgo/data",
			SFTPGoAuthCacheTime: test.cacheTime,
		}

		err := config.Validate()
		if test.wantErr && err == nil {
			t.Errorf("Validate() accepted a cache time of %d, want an error", test.cacheTime)
		}
		if !test.wantErr && err != nil {
			t.Errorf("Validate() rejected a cache time of %d: %v", test.cacheTime, err)
		}
	}
}
