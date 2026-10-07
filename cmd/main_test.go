package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/cyverse/sftpgo-auth-irods/commons"
	"github.com/cyverse/sftpgo-auth-irods/types"
	log "github.com/sirupsen/logrus"
)

// These tests never contact an iRODS server, so the fixtures name a host, zone
// and user that do not exist. irods.example.com is under a domain RFC 2606
// reserves for documentation, so it cannot resolve to real infrastructure.
const (
	testIRODSHost     = "irods.example.com"
	testIRODSPort     = "1247"
	testIRODSEndpoint = testIRODSHost + ":" + testIRODSPort
	testIRODSZone     = "testZone"
	testUsername      = "testuser"
	testUserPassword  = "test-user-password"
	testProxyUsername = "testproxy"
	testProxyPassword = "test-proxy-password"
	testCACertPath    = "/nonexistent/test-ca.crt"

	testUserHome  = "/" + testIRODSZone + "/home/" + testUsername
	testSharedDir = "/" + testIRODSZone + "/home/shared"
)

// TestMain silences the logger and points the iRODS operations at stubs that
// fail the test. A test that forgets stubAuth then fails with a clear message
// instead of trying to reach a server.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)

	authViaPassword = func(*commons.Config) (bool, error) {
		panic("authViaPassword would contact a real iRODS server, call stubAuth first")
	}
	authViaPublicKey = func(*commons.Config) (bool, []string, error) {
		panic("authViaPublicKey would contact a real iRODS server, call stubAuth first")
	}
	createSshDir = func(*commons.Config) error {
		panic("createSshDir would contact a real iRODS server, call stubAuth first")
	}

	os.Exit(m.Run())
}

// configEnvKeys lists every environment variable the configuration reads. The
// helpers below clear all of them before applying a case so that the ambient
// environment cannot leak into a test.
var configEnvKeys = []string{
	"IRODS_PROXY_USER",
	"IRODS_PROXY_PASSWORD",
	"IRODS_HOST",
	"IRODS_PORT",
	"IRODS_ZONE",
	"IRODS_AUTH_SCHEME",
	"IRODS_REQUIRE_CS_NEGOTIATION",
	"IRODS_CS_NEGOTIATION_POLICY",
	"IRODS_SSL_CA_CERT_PATH",
	"IRODS_SSL_ALGORITHM",
	"IRODS_SSL_KEY_SIZE",
	"IRODS_SSL_SALT_SIZE",
	"IRODS_SSL_HASH_ROUNDS",
	"IRODS_SSL_VERIFY_SERVER",
	"IRODS_SHARED",
	"SFTPGO_HOME_PATH",
	"SFTPGO_AUTHD_USERNAME",
	"SFTPGO_AUTHD_PASSWORD",
	"SFTPGO_AUTHD_PUBLIC_KEY",
	"SFTPGO_AUTHD_IP",
	"SFTPGO_LOG_DIR",
	"SFTPGO_API_BASE_URL",
	"SFTPGO_API_KEY",
}

// testPublicKey and otherTestPublicKey are real ed25519 keys. The iRODS calls
// are stubbed out so they are never parsed, but they keep the fixtures
// realistic and share the key type prefix that used to collide.
const (
	testPublicKey      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPUMX76a+rI85n9DwFepwtQDGM2ynvHWEL9ZuDFXzRxT test1@example.com"
	otherTestPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEQWq1N2hDD1MoGdJnw5c2LEr78lr7xcRGSXR1xYd7HG test2@example.com"
)

// setEnv clears every configuration variable and then applies env, restoring
// the original environment when the test ends. An empty value is not the same
// as unset for the int and bool fields, so clearing has to unset.
//
// The environment is process wide, so these tests must not call t.Parallel.
func setEnv(t *testing.T, env map[string]string) {
	t.Helper()

	known := map[string]bool{}
	for _, key := range configEnvKeys {
		known[key] = true

		original, wasSet := os.LookupEnv(key)
		t.Cleanup(func() {
			if wasSet {
				os.Setenv(key, original)
			} else {
				os.Unsetenv(key)
			}
		})

		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("failed to clear %s: %v", key, err)
		}
	}

	for key, value := range env {
		if !known[key] {
			t.Fatalf("%s is missing from configEnvKeys, so it would not be cleaned up", key)
		}
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("failed to set %s: %v", key, err)
		}
	}
}

// readConfig applies env and returns the parsed and validated configuration.
func readConfig(t *testing.T, env map[string]string) *commons.Config {
	t.Helper()

	setEnv(t, env)

	config, err := commons.ReadFromEnv()
	if err != nil {
		t.Fatalf("ReadFromEnv() failed: %v", err)
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	return config
}

// stubAuth forces the iRODS calls to the given outcome for the duration of the
// test. loggedIn and err decide whether authentication succeeds, and options
// are the authorized_keys options the public key path sees.
func stubAuth(t *testing.T, loggedIn bool, options []string, err error) {
	t.Helper()

	origPassword, origPublicKey, origCreateSshDir := authViaPassword, authViaPublicKey, createSshDir
	t.Cleanup(func() {
		authViaPassword, authViaPublicKey, createSshDir = origPassword, origPublicKey, origCreateSshDir
	})

	authViaPassword = func(*commons.Config) (bool, error) {
		return loggedIn, err
	}
	authViaPublicKey = func(*commons.Config) (bool, []string, error) {
		return loggedIn, options, err
	}
	createSshDir = func(*commons.Config) error {
		return nil
	}
}

// baseEnv mirrors the settings every former test script shared.
func baseEnv() map[string]string {
	return map[string]string{
		"IRODS_HOST":                   testIRODSHost,
		"IRODS_PORT":                   testIRODSPort,
		"IRODS_ZONE":                   testIRODSZone,
		"IRODS_REQUIRE_CS_NEGOTIATION": "true",
		"IRODS_CS_NEGOTIATION_POLICY":  "CS_NEG_DONT_CARE",
		"SFTPGO_AUTHD_USERNAME":        testUsername,
		"SFTPGO_AUTHD_IP":              "10.10.10.10",
	}
}

// withSSL adds the SSL settings the PAM scenarios require.
func withSSL(env map[string]string) map[string]string {
	env["IRODS_SSL_CA_CERT_PATH"] = testCACertPath
	env["IRODS_SSL_ALGORITHM"] = "AES-256-CBC"
	env["IRODS_SSL_KEY_SIZE"] = "32"
	env["IRODS_SSL_SALT_SIZE"] = "8"
	env["IRODS_SSL_HASH_ROUNDS"] = "16"
	return env
}

// virtualFolderNames returns the folder names in a stable order.
func virtualFolderNames(user *types.SFTPGoUser) []string {
	names := []string{}
	for _, vfolder := range user.VirtualFolders {
		names = append(names, vfolder.Name)
	}
	sort.Strings(names)
	return names
}

// findVirtualFolder returns the folder with the given name.
func findVirtualFolder(t *testing.T, user *types.SFTPGoUser, name string) types.SFTPGoVirtualFolder {
	t.Helper()

	for _, vfolder := range user.VirtualFolders {
		if vfolder.Name == name {
			return vfolder
		}
	}

	t.Fatalf("virtual folder %q not found, have %v", name, virtualFolderNames(user))
	return types.SFTPGoVirtualFolder{}
}

// TestPasswordAuthScenarios covers what test_password_native.sh,
// test_password_pam.sh and test_password_pam_for_users.sh used to check.
func TestPasswordAuthScenarios(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		// wantAuthScheme is the scheme handed to SFTPGo for the mounted folders
		wantAuthScheme string
		wantPassword   string
	}{
		{
			name: "native",
			env: func() map[string]string {
				env := baseEnv()
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				return env
			}(),
			wantAuthScheme: "native",
			wantPassword:   testUserPassword,
		},
		{
			name: "pam",
			env: func() map[string]string {
				env := withSSL(baseEnv())
				env["IRODS_AUTH_SCHEME"] = "pam"
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				return env
			}(),
			wantAuthScheme: "pam",
			wantPassword:   testUserPassword,
		},
		{
			name: "pam_for_users without proxy falls back to pam",
			env: func() map[string]string {
				env := withSSL(baseEnv())
				env["IRODS_AUTH_SCHEME"] = "pam_for_users"
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				return env
			}(),
			wantAuthScheme: "pam",
			wantPassword:   testUserPassword,
		},
		{
			name: "pam_for_users with proxy uses native and the proxy password",
			env: func() map[string]string {
				env := withSSL(baseEnv())
				env["IRODS_AUTH_SCHEME"] = "pam_for_users"
				env["IRODS_PROXY_USER"] = testProxyUsername
				env["IRODS_PROXY_PASSWORD"] = testProxyPassword
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				return env
			}(),
			wantAuthScheme: "native",
			wantPassword:   testProxyPassword,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := readConfig(t, test.env)
			stubAuth(t, true, nil, nil)

			user, err := authPassword(config)
			if err != nil {
				t.Fatalf("authPassword() failed: %v", err)
			}

			if user.Username != testUsername {
				t.Errorf("username = %q, want %q", user.Username, testUsername)
			}
			if user.Status != 1 {
				t.Errorf("status = %d, want 1", user.Status)
			}
			if want := "/srv/sftpgo/data/" + testUsername; user.HomeDir != want {
				t.Errorf("home dir = %q, want %q", user.HomeDir, want)
			}

			if got, want := virtualFolderNames(user), []string{testUsername + "_home"}; !equalStrings(got, want) {
				t.Fatalf("virtual folders = %v, want %v", got, want)
			}

			home := findVirtualFolder(t, user, testUsername+"_home")
			if want := testUserHome; home.FileSystem.IRODSConfig.CollectionPath != want {
				t.Errorf("collection path = %q, want %q", home.FileSystem.IRODSConfig.CollectionPath, want)
			}
			if got := home.FileSystem.IRODSConfig.AuthScheme; got != test.wantAuthScheme {
				t.Errorf("auth scheme = %q, want %q", got, test.wantAuthScheme)
			}
			if got := home.FileSystem.IRODSConfig.Password.Payload; got != test.wantPassword {
				t.Errorf("password payload = %q, want %q", got, test.wantPassword)
			}
			if want := testIRODSEndpoint; home.FileSystem.IRODSConfig.Endpoint != want {
				t.Errorf("endpoint = %q, want %q", home.FileSystem.IRODSConfig.Endpoint, want)
			}
		})
	}
}

// TestPublicKeyAuthScenarios covers what test_publickey.sh and
// test_publickey_pam_for_users.sh used to check.
func TestPublicKeyAuthScenarios(t *testing.T) {
	t.Run("with proxy", func(t *testing.T) {
		env := baseEnv()
		env["IRODS_PROXY_USER"] = testProxyUsername
		env["IRODS_PROXY_PASSWORD"] = testProxyPassword
		env["SFTPGO_AUTHD_PUBLIC_KEY"] = testPublicKey

		config := readConfig(t, env)
		stubAuth(t, true, nil, nil)

		user, err := authPublicKey(config)
		if err != nil {
			t.Fatalf("authPublicKey() failed: %v", err)
		}

		if user.Username != testUsername {
			t.Errorf("username = %q, want %q", user.Username, testUsername)
		}
		if got, want := virtualFolderNames(user), []string{testUsername + "_home"}; !equalStrings(got, want) {
			t.Fatalf("virtual folders = %v, want %v", got, want)
		}

		home := findVirtualFolder(t, user, testUsername+"_home")
		if want := testUserHome; home.FileSystem.IRODSConfig.CollectionPath != want {
			t.Errorf("collection path = %q, want %q", home.FileSystem.IRODSConfig.CollectionPath, want)
		}
		// public key auth goes through the proxy account
		if got, want := home.FileSystem.IRODSConfig.ProxyUsername, testProxyUsername; got != want {
			t.Errorf("proxy username = %q, want %q", got, want)
		}
		if got, want := home.FileSystem.IRODSConfig.Password.Payload, testProxyPassword; got != want {
			t.Errorf("password payload = %q, want %q", got, want)
		}
	})

	t.Run("pam_for_users without proxy is rejected", func(t *testing.T) {
		env := withSSL(baseEnv())
		env["IRODS_AUTH_SCHEME"] = "pam_for_users"
		env["SFTPGO_AUTHD_PUBLIC_KEY"] = testPublicKey

		config := readConfig(t, env)
		stubAuth(t, true, nil, nil)

		// public key auth reads authorized_keys with the proxy account, so a
		// missing proxy user has to fail before any iRODS call
		if _, err := authPublicKey(config); err == nil {
			t.Fatal("authPublicKey() succeeded without a proxy user, want an error")
		} else if !strings.Contains(err.Error(), "proxy username") {
			t.Errorf("error = %v, want it to mention the proxy username", err)
		}
	})
}

// TestPublicKeyAuthHomeOption checks that a home= option in authorized_keys
// produces a separate SFTPGo user confined to that collection.
func TestPublicKeyAuthHomeOption(t *testing.T) {
	env := baseEnv()
	env["IRODS_PROXY_USER"] = testProxyUsername
	env["IRODS_PROXY_PASSWORD"] = testProxyPassword
	env["SFTPGO_AUTHD_PUBLIC_KEY"] = testPublicKey

	config := readConfig(t, env)
	stubAuth(t, true, []string{fmt.Sprintf("home=%q", testUserHome+"/projA")}, nil)

	user, err := authPublicKey(config)
	if err != nil {
		t.Fatalf("authPublicKey() failed: %v", err)
	}

	// the user name is suffixed with a per key name so that two keys with
	// different home options cannot collide
	if !strings.HasPrefix(user.Username, testUsername+"_") || user.Username == testUsername+"_" {
		t.Fatalf("username = %q, want a %s_<key name> form", user.Username, testUsername)
	}
	if user.Username == testUsername {
		t.Fatal("username was not suffixed, the custom home path was ignored")
	}

	if len(user.VirtualFolders) != 1 {
		t.Fatalf("virtual folders = %v, want exactly one", virtualFolderNames(user))
	}
	home := user.VirtualFolders[0]
	if want := testUserHome + "/projA"; home.FileSystem.IRODSConfig.CollectionPath != want {
		t.Errorf("collection path = %q, want %q", home.FileSystem.IRODSConfig.CollectionPath, want)
	}
	// the folder is still mounted under the iRODS user name
	if want := "/" + testUsername; home.VirtualPath != want {
		t.Errorf("virtual path = %q, want %q", home.VirtualPath, want)
	}
}

// TestPublicKeyNameDistinguishesKeys checks that two keys of the same type do
// not collapse onto the same SFTPGo user name.
func TestPublicKeyNameDistinguishesKeys(t *testing.T) {
	first := makeSafePublickKeyName(testPublicKey)
	second := makeSafePublickKeyName(otherTestPublicKey)

	if first == second {
		t.Errorf("two different ed25519 keys produced the same name %q", first)
	}
	if first != makeSafePublickKeyName(testPublicKey) {
		t.Error("the name is not stable across calls for the same key")
	}
	for _, name := range []string{first, second} {
		if strings.ContainsAny(name, "/+= ") {
			t.Errorf("name %q contains a character that is unsafe in a path or URL", name)
		}
	}
}

// TestAuthFailure checks that a rejected or failing iRODS login does not
// produce a user.
func TestAuthFailure(t *testing.T) {
	passwordEnv := func() map[string]string {
		env := baseEnv()
		env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
		return env
	}
	publicKeyEnv := func() map[string]string {
		env := baseEnv()
		env["IRODS_PROXY_USER"] = testProxyUsername
		env["IRODS_PROXY_PASSWORD"] = testProxyPassword
		env["SFTPGO_AUTHD_PUBLIC_KEY"] = testPublicKey
		return env
	}

	tests := []struct {
		name      string
		env       map[string]string
		loggedIn  bool
		stubErr   error
		publicKey bool
	}{
		{name: "password rejected", env: passwordEnv(), loggedIn: false},
		{
			name:    "password errored",
			env:     passwordEnv(),
			stubErr: errors.New("connection refused"),
		},
		{name: "public key rejected", env: publicKeyEnv(), publicKey: true},
		{
			name:      "public key errored",
			env:       publicKeyEnv(),
			stubErr:   errors.New("authorized_keys not found"),
			publicKey: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := readConfig(t, test.env)
			stubAuth(t, test.loggedIn, nil, test.stubErr)

			var user *types.SFTPGoUser
			var err error
			if test.publicKey {
				user, err = authPublicKey(config)
			} else {
				user, err = authPassword(config)
			}

			if err == nil {
				t.Fatal("authentication succeeded, want an error")
			}
			if user != nil {
				t.Errorf("user = %+v, want nil on failure", user)
			}
		})
	}
}

// TestAnonymousUser checks the anonymous path: no home directory and an empty
// password, regardless of what was supplied.
func TestAnonymousUser(t *testing.T) {
	env := baseEnv()
	env["SFTPGO_AUTHD_USERNAME"] = "ANONYMOUS"
	env["SFTPGO_AUTHD_PASSWORD"] = "ignored"
	env["IRODS_SHARED"] = testSharedDir

	config := readConfig(t, env)
	stubAuth(t, true, nil, nil)

	user, err := authPassword(config)
	if err != nil {
		t.Fatalf("authPassword() failed: %v", err)
	}

	if user.Username != "anonymous" {
		t.Errorf("username = %q, want %q", user.Username, "anonymous")
	}
	// only the shared folder, no home
	if got, want := virtualFolderNames(user), []string{"anonymous_shared"}; !equalStrings(got, want) {
		t.Fatalf("virtual folders = %v, want %v", got, want)
	}

	shared := findVirtualFolder(t, user, "anonymous_shared")
	if got := shared.FileSystem.IRODSConfig.Password.Payload; got != "" {
		t.Errorf("password payload = %q, want it emptied for anonymous", got)
	}
	if want := testSharedDir; shared.FileSystem.IRODSConfig.CollectionPath != want {
		t.Errorf("collection path = %q, want %q", shared.FileSystem.IRODSConfig.CollectionPath, want)
	}
}

// TestSharedDir checks that IRODS_SHARED adds a second mounted folder.
func TestSharedDir(t *testing.T) {
	env := baseEnv()
	env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
	env["IRODS_SHARED"] = testSharedDir

	config := readConfig(t, env)
	stubAuth(t, true, nil, nil)

	user, err := authPassword(config)
	if err != nil {
		t.Fatalf("authPassword() failed: %v", err)
	}

	want := []string{testUsername + "_home", testUsername + "_shared"}
	if got := virtualFolderNames(user); !equalStrings(got, want) {
		t.Fatalf("virtual folders = %v, want %v", got, want)
	}

	// '/' is listable and every mounted folder is fully accessible
	for _, path := range []string{"/", "/" + testUsername, "/shared"} {
		if _, ok := user.Permissions[path]; !ok {
			t.Errorf("permissions are missing an entry for %q, have %v", path, user.Permissions)
		}
	}
	if got := user.Permissions["/"]; !equalStrings(got, []string{"list"}) {
		t.Errorf("permissions for / = %v, want [list]", got)
	}
}

// TestRedactedJSONHidesPassword checks that the logged representation does not
// carry the password, while the response sent to SFTPGo still does.
func TestRedactedJSONHidesPassword(t *testing.T) {
	env := baseEnv()
	env["SFTPGO_AUTHD_PASSWORD"] = "super-secret"

	config := readConfig(t, env)
	stubAuth(t, true, nil, nil)

	user, err := authPassword(config)
	if err != nil {
		t.Fatalf("authPassword() failed: %v", err)
	}

	redacted := user.GetRedactedJSONString()
	if strings.Contains(redacted, "super-secret") {
		t.Error("the redacted JSON still contains the password")
	}

	// decode rather than match on the text, because encoding/json escapes the
	// angle brackets of the placeholder
	var decoded types.SFTPGoUser
	if err := json.Unmarshal([]byte(redacted), &decoded); err != nil {
		t.Fatalf("failed to decode the redacted JSON: %v", err)
	}
	if len(decoded.VirtualFolders) == 0 {
		t.Fatal("the redacted JSON has no virtual folders")
	}
	if got, want := decoded.VirtualFolders[0].FileSystem.IRODSConfig.Password.Payload, "<redacted>"; got != want {
		t.Errorf("redacted password payload = %q, want %q", got, want)
	}

	response, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("failed to marshal the user: %v", err)
	}
	if !strings.Contains(string(response), "super-secret") {
		t.Error("the response to SFTPGo lost the password")
	}
}

// TestEnsureVirtualFoldersViaAPI checks that the folders are created through the
// SFTPGo REST API when it is configured.
func TestEnsureVirtualFoldersViaAPI(t *testing.T) {
	var gets, posts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-SFTPGO-API-KEY") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet {
			gets = append(gets, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var folder types.SFTPGoFolder
		if err := json.NewDecoder(r.Body).Decode(&folder); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		posts = append(posts, folder.Name)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	env := baseEnv()
	env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
	env["IRODS_SHARED"] = testSharedDir
	env["SFTPGO_API_BASE_URL"] = server.URL
	env["SFTPGO_API_KEY"] = "test-key"

	config := readConfig(t, env)
	stubAuth(t, true, nil, nil)

	if _, err := authPassword(config); err != nil {
		t.Fatalf("authPassword() failed: %v", err)
	}

	wantGets := []string{"/api/v2/folders/" + testUsername + "_home", "/api/v2/folders/" + testUsername + "_shared"}
	sort.Strings(gets)
	if !equalStrings(gets, wantGets) {
		t.Errorf("looked up %v, want %v", gets, wantGets)
	}

	wantPosts := []string{testUsername + "_home", testUsername + "_shared"}
	sort.Strings(posts)
	if !equalStrings(posts, wantPosts) {
		t.Errorf("created %v, want %v", posts, wantPosts)
	}
}

// TestEnsureVirtualFoldersAPIFailure checks that a failing REST API fails the
// authentication rather than returning a user SFTPGo cannot mount.
func TestEnsureVirtualFoldersAPIFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	env := baseEnv()
	env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
	env["SFTPGO_API_BASE_URL"] = server.URL
	env["SFTPGO_API_KEY"] = "test-key"

	config := readConfig(t, env)
	stubAuth(t, true, nil, nil)

	user, err := authPassword(config)
	if err == nil {
		t.Fatal("authPassword() succeeded with a failing REST API, want an error")
	}
	if user != nil {
		t.Errorf("user = %+v, want nil", user)
	}
}

// TestConfigValidation covers the configuration errors the former scripts could
// only surface by running the binary.
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name: "no credentials",
			env: func() map[string]string {
				return baseEnv()
			}(),
			wantErr: "at least any of password or public key must be given",
		},
		{
			name: "no host",
			env: func() map[string]string {
				env := baseEnv()
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				delete(env, "IRODS_HOST")
				return env
			}(),
			wantErr: "iRODS host is not given",
		},
		{
			name: "no zone",
			env: func() map[string]string {
				env := baseEnv()
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				delete(env, "IRODS_ZONE")
				return env
			}(),
			wantErr: "iRODS zone is not given",
		},
		{
			name: "no ip",
			env: func() map[string]string {
				env := baseEnv()
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				delete(env, "SFTPGO_AUTHD_IP")
				return env
			}(),
			wantErr: "ip address is not given",
		},
		{
			name: "pam without cs negotiation",
			env: func() map[string]string {
				env := withSSL(baseEnv())
				env["IRODS_AUTH_SCHEME"] = "pam"
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				env["IRODS_REQUIRE_CS_NEGOTIATION"] = "false"
				return env
			}(),
			wantErr: "client-server negotiation is not given for PAM authentication",
		},
		{
			name: "pam without ssl settings",
			env: func() map[string]string {
				env := baseEnv()
				env["IRODS_AUTH_SCHEME"] = "pam"
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				return env
			}(),
			wantErr: "iRODS SSL CA certificate path is not given",
		},
		{
			name: "cs_neg_require without ssl settings",
			env: func() map[string]string {
				env := baseEnv()
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				env["IRODS_CS_NEGOTIATION_POLICY"] = "CS_NEG_REQUIRE"
				return env
			}(),
			wantErr: "iRODS SSL CA certificate path is not given",
		},
		{
			name: "unknown cs negotiation policy",
			env: func() map[string]string {
				env := baseEnv()
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				env["IRODS_CS_NEGOTIATION_POLICY"] = "CS_NEG_REQUIER"
				return env
			}(),
			wantErr: "must be one of CS_NEG_REFUSE, CS_NEG_REQUIRE or CS_NEG_DONT_CARE",
		},
		{
			name: "unknown ssl verify server",
			env: func() map[string]string {
				env := baseEnv()
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				env["IRODS_SSL_VERIFY_SERVER"] = "bogus"
				return env
			}(),
			wantErr: "must be one of none, cert or hostname",
		},
		{
			name: "api base url without key",
			env: func() map[string]string {
				env := baseEnv()
				env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
				env["SFTPGO_API_BASE_URL"] = "http://localhost:8080"
				return env
			}(),
			wantErr: "must be set together",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEnv(t, test.env)

			config, err := commons.ReadFromEnv()
			if err != nil {
				t.Fatalf("ReadFromEnv() failed: %v", err)
			}

			err = config.Validate()
			if err == nil {
				t.Fatal("Validate() succeeded, want an error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, test.wantErr)
			}
		})
	}
}

// TestConfigDefaults checks the values filled in when the environment omits
// them.
func TestConfigDefaults(t *testing.T) {
	env := map[string]string{
		"IRODS_HOST":            testIRODSHost,
		"IRODS_ZONE":            testIRODSZone,
		"SFTPGO_AUTHD_USERNAME": testUsername,
		"SFTPGO_AUTHD_PASSWORD": testUserPassword,
		"SFTPGO_AUTHD_IP":       "10.10.10.10",
	}

	config := readConfig(t, env)

	if config.IRODSPort != 1247 {
		t.Errorf("port = %d, want 1247", config.IRODSPort)
	}
	if config.IRODSAuthScheme != "native" {
		t.Errorf("auth scheme = %q, want native", config.IRODSAuthScheme)
	}
	if config.IRODSCSNegotiationPolicy != "CS_NEG_DONT_CARE" {
		t.Errorf("cs negotiation policy = %q, want CS_NEG_DONT_CARE", config.IRODSCSNegotiationPolicy)
	}
	if config.IRODSSSLVerifyServer != commons.SSLVerifyServerNone {
		t.Errorf("ssl verify server = %q, want %q", config.IRODSSSLVerifyServer, commons.SSLVerifyServerNone)
	}
	if config.SFTPGoHomeDir != "/srv/sftpgo/data" {
		t.Errorf("home dir = %q, want /srv/sftpgo/data", config.SFTPGoHomeDir)
	}
	if config.SFTPGoLogDir != "/tmp" {
		t.Errorf("log dir = %q, want /tmp", config.SFTPGoLogDir)
	}
}

// TestConfigNormalization checks that case and surrounding space do not change
// how a setting is interpreted.
func TestConfigNormalization(t *testing.T) {
	env := baseEnv()
	env["SFTPGO_AUTHD_PASSWORD"] = testUserPassword
	env["IRODS_CS_NEGOTIATION_POLICY"] = " cs_neg_dont_care "
	env["IRODS_SSL_VERIFY_SERVER"] = " HostName "

	config := readConfig(t, env)

	if config.IRODSCSNegotiationPolicy != "CS_NEG_DONT_CARE" {
		t.Errorf("cs negotiation policy = %q, want CS_NEG_DONT_CARE", config.IRODSCSNegotiationPolicy)
	}
	if config.IRODSSSLVerifyServer != commons.SSLVerifyServerHostname {
		t.Errorf("ssl verify server = %q, want %q", config.IRODSSSLVerifyServer, commons.SSLVerifyServerHostname)
	}
}

// TestIsPublicKeyAuth checks which authentication path a request takes.
func TestIsPublicKeyAuth(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		publicKey string
		want      bool
	}{
		{name: "public key given", username: testUsername, publicKey: testPublicKey, want: true},
		{name: "no public key", username: testUsername, want: false},
		{name: "anonymous ignores the public key", username: "anonymous", publicKey: testPublicKey, want: false},
		{name: "anonymous in upper case", username: "ANONYMOUS", publicKey: testPublicKey, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &commons.Config{
				SFTPGoAuthdUsername:  test.username,
				SFTPGoAuthdPublickey: test.publicKey,
			}

			if got := config.IsPublicKeyAuth(); got != test.want {
				t.Errorf("IsPublicKeyAuth() = %v, want %v", got, test.want)
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
