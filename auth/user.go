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

func makeLocalUserPath(config *types.Config) string {
	return path.Join(homeDirPrefix, config.SFTPGoAuthdUsername)
}

func makeLocalUserHomePath(config *types.Config) string {
	return path.Join(homeDirPrefix, config.SFTPGoAuthdUsername, config.SFTPGoAuthdUsername)
}

func makeLocalUserSharedPath(config *types.Config) string {
	return path.Join(homeDirPrefix, config.SFTPGoAuthdUsername, "shared")
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

func makeFileSystem(config *types.Config, collectionPath string) *types.SFTPGoFileSystem {
	return &types.SFTPGoFileSystem{
		Provider: iRODSFsProvider,
		IRODSConfig: &types.SFTPGoIRODSFsConfig{
			Endpoint:       fmt.Sprintf("%s:%d", config.IRODSHost, config.IRODSPort),
			Username:       config.SFTPGoAuthdUsername,
			ProxyUsername:  config.IRODSProxyUsername,
			Password:       types.NewSFTPGoSecretForUserPassword(config.IRODSProxyPassword),
			CollectionPath: collectionPath,
			Resource:       "",
		},
	}
}

func makeVirtualFolders(config *types.Config) []types.SFTPGoVirtualFolder {
	sharedPath := makeIRODSSharedPath(config)
	homePath := makeIRODSHomePath(config)

	fsShared := makeFileSystem(config, sharedPath)
	fsHome := makeFileSystem(config, homePath)

	vfolderHome := types.SFTPGoVirtualFolder{
		Name:        fmt.Sprintf("%s_home", config.SFTPGoAuthdUsername),
		Description: fmt.Sprintf("%s's home dir", config.SFTPGoAuthdUsername),
		//MappedPath:  makeLocalUserHomePath(config),
		VirtualPath: fmt.Sprintf("/%s", config.SFTPGoAuthdUsername),
		FileSystem:  fsHome,
	}

	vfolderShared := types.SFTPGoVirtualFolder{
		Name:        fmt.Sprintf("%s_shared", config.SFTPGoAuthdUsername),
		Description: fmt.Sprintf("%s's shared dir", config.SFTPGoAuthdUsername),
		//MappedPath:  makeLocalUserSharedPath(config),
		VirtualPath: "/shared",
		FileSystem:  fsShared,
	}

	return []types.SFTPGoVirtualFolder{
		vfolderHome, vfolderShared,
	}
}

func MakeSFTPGoUser(config *types.Config) *types.SFTPGoUser {
	localFs := makeLocalFileSystem()
	return &types.SFTPGoUser{
		Status:         1,
		Username:       config.SFTPGoAuthdUsername,
		HomeDir:        makeLocalUserPath(config),
		VirtualFolders: makeVirtualFolders(config),
		Permissions:    makePermissions(config),
		Filters:        makeFilters(config),
		FileSystem:     localFs,
	}
}
