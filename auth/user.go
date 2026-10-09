package auth

import (
	"fmt"
	"path"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/cyverse/sftpgo-auth-irods/commons"
	"github.com/cyverse/sftpgo-auth-irods/types"
	"github.com/sftpgo/sdk"
	log "github.com/sirupsen/logrus"
)

func makeLocalUserPath(config *commons.Config, sftpgoUsername string) string {
	return path.Join(config.SFTPGoHomeDir, sftpgoUsername)
}

func makeLocalUserSubPath(config *commons.Config, sftpgoUsername string, name string) string {
	return path.Join(config.SFTPGoHomeDir, sftpgoUsername, name)
}

func makePermissions(mountPaths []types.MountPath) map[string][]string {
	permissions := make(map[string][]string)
	permissions["/"] = []string{"list"}

	for _, mountPath := range mountPaths {
		p := fmt.Sprintf("/%s", mountPath.DirName)
		permissions[p] = []string{"*"}
	}

	return permissions
}

func makeFilters(config *commons.Config) *types.SFTPGoUserFilter {
	return &types.SFTPGoUserFilter{
		AllowedIP:          []string{},
		DeniedLoginMethods: []string{},
		// let SFTPGo reuse this result instead of calling the hook, and us
		// iRODS, again for every login
		ExternalAuthCacheTime: config.SFTPGoAuthCacheTime,
	}
}

func makeLocalFileSystem() *types.SFTPGoFileSystem {
	return &types.SFTPGoFileSystem{
		Provider: sdk.LocalFilesystemProvider,
	}
}

func makeFileSystem(config *commons.Config, collectionPath string) *types.SFTPGoFileSystem {
	authScheme := config.IRODSAuthScheme
	if strings.ToLower(config.IRODSAuthScheme) == "pam_for_users" {
		if config.IsProxyAuth() {
			authScheme = "native"
		} else {
			authScheme = "pam"
		}
	}

	password := config.SFTPGoAuthdPassword
	if len(config.IRODSProxyUsername) > 0 {
		password = config.IRODSProxyPassword
	}

	return &types.SFTPGoFileSystem{
		Provider: sdk.IRODSFilesystemProvider,
		IRODSConfig: &types.SFTPGoIRODSFsConfig{
			Endpoint:                       fmt.Sprintf("%s:%d", config.IRODSHost, config.IRODSPort),
			Username:                       config.SFTPGoAuthdUsername,
			ProxyUsername:                  config.IRODSProxyUsername,
			Password:                       types.NewSFTPGoSecretForUserPassword(password),
			CollectionPath:                 collectionPath,
			Resource:                       "",
			AuthScheme:                     authScheme,
			RequireClientServerNegotiation: config.IRODSRequireCSNegotiation,
			ClientServerNegotiationPolicy:  config.IRODSCSNegotiationPolicy,
			SSLCACertificatePath:           config.IRODSSSLCACertificatePath,
			SSLKeySize:                     config.IRODSSSLKeySize,
			SSLAlgorithm:                   config.IRODSSSLAlgorithm,
			SSLSaltSize:                    config.IRODSSSLSaltSize,
			SSLHashRounds:                  config.IRODSSSLHashRounds,
			PoolEndpoint:                   config.IRODSPoolEndpoint,
		},
	}
}

func makeVirtualFolders(config *commons.Config, sftpgoUsername string, mountPaths []types.MountPath) ([]types.SFTPGoVirtualFolder, error) {
	vfolders := []types.SFTPGoVirtualFolder{}
	reservedNames := map[string]bool{}
	reservedPaths := map[string]bool{}

	for _, mountPath := range mountPaths {
		if _, ok := reservedNames[mountPath.Name]; ok {
			// already reserved name
			return nil, errors.Errorf("duplicated virtual folder name %q", mountPath.Name)
		}

		virtualPath := fmt.Sprintf("/%s", mountPath.DirName)
		if _, ok := reservedPaths[virtualPath]; ok {
			// a second folder at the same path would shadow the first one.
			// Mount paths are ordered with the home first, so dropping this one
			// keeps the home reachable instead of failing the login.
			log.Warnf("skipping virtual folder %q: it would mount at %q, which is already taken", mountPath.Name, virtualPath)
			continue
		}

		vfolder := types.SFTPGoVirtualFolder{
			Name:        mountPath.Name,
			Description: mountPath.Description,
			MappedPath:  makeLocalUserSubPath(config, sftpgoUsername, mountPath.DirName),
			VirtualPath: virtualPath,
			FileSystem:  makeFileSystem(config, mountPath.CollectionPath),
		}

		vfolders = append(vfolders, vfolder)

		reservedNames[mountPath.Name] = true
		reservedPaths[virtualPath] = true
	}

	return vfolders, nil
}

func MakeSFTPGoUser(config *commons.Config, sftpgoUsername string, mountPaths []types.MountPath) (*types.SFTPGoUser, error) {
	vfolders, err := makeVirtualFolders(config, sftpgoUsername, mountPaths)
	if err != nil {
		return nil, err
	}

	if config.HasSFTPGoAPI() {
		if err := EnsureVirtualFolders(config, vfolders); err != nil {
			return nil, errors.Wrap(err, "failed to ensure virtual folders in SFTPGo")
		}
	}

	return &types.SFTPGoUser{
		Status:         1,
		Username:       sftpgoUsername,
		HomeDir:        makeLocalUserPath(config, sftpgoUsername),
		VirtualFolders: vfolders,
		Permissions:    makePermissions(mountPaths),
		Filters:        makeFilters(config),
		FileSystem:     makeLocalFileSystem(),
	}, nil
}
