package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func irodsFileSystem(password string) *SFTPGoFileSystem {
	return &SFTPGoFileSystem{
		IRODSConfig: &SFTPGoIRODSFsConfig{
			Endpoint:       "irods.example.com:1247",
			Username:       "testuser",
			CollectionPath: "/testZone/home/testuser",
			Password:       NewSFTPGoSecretForUserPassword(password),
		},
	}
}

// TestGetRedactedNilReceivers checks that redacting tolerates a nil pointer.
// GetRedactedJSONString runs on the success path, so a panic here would turn an
// authenticated request into a crash with no JSON response.
func TestGetRedactedNilReceivers(t *testing.T) {
	t.Run("nil iRODS config", func(t *testing.T) {
		var config *SFTPGoIRODSFsConfig
		if got := config.GetRedacted(); got != nil {
			t.Errorf("GetRedacted() = %+v, want nil", got)
		}
	})

	t.Run("nil filesystem", func(t *testing.T) {
		var fs *SFTPGoFileSystem
		if got := fs.GetRedacted(); got != nil {
			t.Errorf("GetRedacted() = %+v, want nil", got)
		}
	})

	t.Run("nil user", func(t *testing.T) {
		var user *SFTPGoUser
		if got := user.GetRedacted(); got != nil {
			t.Errorf("GetRedacted() = %+v, want nil", got)
		}
	})

	t.Run("filesystem without an iRODS config", func(t *testing.T) {
		fs := &SFTPGoFileSystem{}
		got := fs.GetRedacted()
		if got == nil {
			t.Fatal("GetRedacted() = nil, want a filesystem")
		}
		if got.IRODSConfig != nil {
			t.Errorf("IRODSConfig = %+v, want nil", got.IRODSConfig)
		}
	})

	t.Run("virtual folder without a filesystem", func(t *testing.T) {
		user := &SFTPGoUser{
			Username:       "testuser",
			VirtualFolders: []SFTPGoVirtualFolder{{Name: "testuser_home"}},
		}

		got := user.GetRedacted()
		if len(got.VirtualFolders) != 1 {
			t.Fatalf("virtual folders = %v, want one", got.VirtualFolders)
		}
		if got.VirtualFolders[0].FileSystem != nil {
			t.Errorf("filesystem = %+v, want nil", got.VirtualFolders[0].FileSystem)
		}
	})

	t.Run("user without a filesystem", func(t *testing.T) {
		user := &SFTPGoUser{Username: "testuser"}
		if got := user.GetRedacted(); got.FileSystem != nil {
			t.Errorf("filesystem = %+v, want nil", got.FileSystem)
		}
	})

	t.Run("decoded from JSON without a filesystem", func(t *testing.T) {
		var user SFTPGoUser
		body := `{"username":"testuser","virtual_folders":[{"name":"testuser_home"}],"filesystem":null}`
		if err := json.Unmarshal([]byte(body), &user); err != nil {
			t.Fatalf("failed to decode: %v", err)
		}

		if got := user.GetRedactedJSONString(); !strings.Contains(got, "testuser") {
			t.Errorf("redacted JSON = %s, want it to carry the user name", got)
		}
	})
}

// TestGetRedactedReplacesPasswords checks that every password in the structure
// is replaced.
func TestGetRedactedReplacesPasswords(t *testing.T) {
	user := &SFTPGoUser{
		Username: "testuser",
		VirtualFolders: []SFTPGoVirtualFolder{
			{Name: "testuser_home", FileSystem: irodsFileSystem("home-secret")},
			{Name: "testuser_shared", FileSystem: irodsFileSystem("shared-secret")},
		},
		FileSystem: irodsFileSystem("user-secret"),
	}

	redacted := user.GetRedacted()

	for _, vfolder := range redacted.VirtualFolders {
		if got := vfolder.FileSystem.IRODSConfig.Password.Payload; got != "<redacted>" {
			t.Errorf("folder %q password = %q, want %q", vfolder.Name, got, "<redacted>")
		}
	}
	if got := redacted.FileSystem.IRODSConfig.Password.Payload; got != "<redacted>" {
		t.Errorf("user password = %q, want %q", got, "<redacted>")
	}

	// the other fields have to survive, otherwise the log is useless
	home := redacted.VirtualFolders[0]
	if want := "/testZone/home/testuser"; home.FileSystem.IRODSConfig.CollectionPath != want {
		t.Errorf("collection path = %q, want %q", home.FileSystem.IRODSConfig.CollectionPath, want)
	}
	if want := "irods.example.com:1247"; home.FileSystem.IRODSConfig.Endpoint != want {
		t.Errorf("endpoint = %q, want %q", home.FileSystem.IRODSConfig.Endpoint, want)
	}
}

// TestGetRedactedLeavesAnEmptyPasswordAlone checks that an anonymous login,
// which carries no password, is not given a placeholder that looks like one.
func TestGetRedactedLeavesAnEmptyPasswordAlone(t *testing.T) {
	user := &SFTPGoUser{
		Username:       "anonymous",
		VirtualFolders: []SFTPGoVirtualFolder{{Name: "anonymous_shared", FileSystem: irodsFileSystem("")}},
	}

	redacted := user.GetRedacted()

	if got := redacted.VirtualFolders[0].FileSystem.IRODSConfig.Password.Payload; got != "" {
		t.Errorf("password payload = %q, want it left empty", got)
	}
}

// TestGetRedactedDoesNotMutateTheOriginal is the load bearing property: the
// caller logs the redacted copy and then marshals the original for SFTPGo, so
// redacting in place would send "<redacted>" as the password.
func TestGetRedactedDoesNotMutateTheOriginal(t *testing.T) {
	user := &SFTPGoUser{
		Username: "testuser",
		VirtualFolders: []SFTPGoVirtualFolder{
			{Name: "testuser_home", FileSystem: irodsFileSystem("home-secret")},
		},
		FileSystem: irodsFileSystem("user-secret"),
	}

	if redacted := user.GetRedacted(); redacted == nil {
		t.Fatal("GetRedacted() = nil")
	}

	if got := user.VirtualFolders[0].FileSystem.IRODSConfig.Password.Payload; got != "home-secret" {
		t.Errorf("the folder password became %q, want it untouched", got)
	}
	if got := user.FileSystem.IRODSConfig.Password.Payload; got != "user-secret" {
		t.Errorf("the user password became %q, want it untouched", got)
	}

	// the same holds for the JSON helper, which is what the caller actually uses
	_ = user.GetRedactedJSONString()

	response, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("failed to marshal the user: %v", err)
	}
	if !strings.Contains(string(response), "home-secret") {
		t.Error("the response to SFTPGo lost the folder password")
	}
	if !strings.Contains(string(response), "user-secret") {
		t.Error("the response to SFTPGo lost the user password")
	}
}
