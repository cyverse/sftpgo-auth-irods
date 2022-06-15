package auth

import (
	"fmt"
	"path"

	"github.com/cyverse/sftpgo-auth-irods/types"
)

const (
	localFsProvider int = 0
	iRODSFsProvider int = 6

	homeDirPrefix string = "/srv/sftpgo/data"
)

func makeLocalHomePath(config *types.Config) string {
	return path.Join(homeDirPrefix, config.SFTPGoAuthdUsername)
}

func makePermissions(config *types.Config) map[string][]string {
	permissions := make(map[string][]string)
	permissions["/"] = []string{"*"}
	return permissions
}

func makeFilters(config *types.Config) *types.SFTPGoUserFilter {
	return &types.SFTPGoUserFilter{
		AllowedIP:          []string{},
		DeniedLoginMethods: []string{},
	}
}

func makeLocalFileSystem() *types.SFTPGoFileSystem {
	return &types.SFTPGoFileSystem{
		Provider: localFsProvider,
	}
}

func makeFileSystem(config *types.Config) *types.SFTPGoFileSystem {
	return &types.SFTPGoFileSystem{
		Provider: iRODSFsProvider,
		IRODSConfig: &types.SFTPGoIRODSFsConfig{
			Endpoint:       fmt.Sprintf("%s:%d", config.IRODSHost, config.IRODSPort),
			Username:       config.SFTPGoAuthdUsername,
			ProxyUsername:  "",
			Password:       types.NewSFTPGoSecretForUserPassword(config.SFTPGoAuthdPassword),
			CollectionPath: makeIRODSHomePath(config),
			Resource:       "",
		},
	}
}

func makeFileSystemForProxy(config *types.Config) *types.SFTPGoFileSystem {
	return &types.SFTPGoFileSystem{
		Provider: iRODSFsProvider,
		IRODSConfig: &types.SFTPGoIRODSFsConfig{
			Endpoint:       fmt.Sprintf("%s:%d", config.IRODSHost, config.IRODSPort),
			Username:       config.SFTPGoAuthdUsername,
			ProxyUsername:  config.IRODSProxyUsername,
			Password:       types.NewSFTPGoSecretForUserPassword(config.IRODSProxyPassword),
			CollectionPath: makeIRODSHomePath(config),
			Resource:       "",
		},
	}
}

func makeVirtualFolders(config *types.Config, proxyUser bool) []types.SFTPGoVirtualFolder {
	var fs *types.SFTPGoFileSystem
	if proxyUser {
		fs = makeFileSystemForProxy(config)
	} else {
		fs = makeFileSystem(config)
	}

	vfolderHome := types.SFTPGoVirtualFolder{
		Name:        fmt.Sprintf("%s_home", config.SFTPGoAuthdUsername),
		Description: fmt.Sprintf("%s's home dir", config.SFTPGoAuthdUsername),
		MappedPath:  makeIRODSHomePath(config),
		VirtualPath: fmt.Sprintf("/%s", config.SFTPGoAuthdUsername),
		FileSystem:  fs,
	}

	vfolderShared := types.SFTPGoVirtualFolder{
		Name:        fmt.Sprintf("%s_shared", config.SFTPGoAuthdUsername),
		Description: fmt.Sprintf("%s's shared dir", config.SFTPGoAuthdUsername),
		MappedPath:  makeIRODSSharedPath(config),
		VirtualPath: "/shared",
		FileSystem:  fs,
	}

	return []types.SFTPGoVirtualFolder{
		vfolderHome, vfolderShared,
	}
}

func MakeSFTPGoUser(config *types.Config, publicKeyAuth bool) *types.SFTPGoUser {
	localFs := makeLocalFileSystem()
	return &types.SFTPGoUser{
		Status:         1,
		Username:       config.SFTPGoAuthdUsername,
		HomeDir:        makeLocalHomePath(config),
		VirtualFolders: makeVirtualFolders(config, publicKeyAuth),
		Permissions:    makePermissions(config),
		Filters:        makeFilters(config),
		FileSystem:     localFs,
	}
}
