package auth

import (
	"fmt"

	"github.com/cyverse/sftpgo-auth-irods/types"
)

const (
	iRODSFsProvider int = 6
)

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

func makeFileSystemForPasswordAuth(config *types.Config) *types.SFTPGoFileSystem {
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

func makeFileSystemForPublicKeyAuth(config *types.Config) *types.SFTPGoFileSystem {
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

func MakeSFTPGoUserForPasswordAuth(config *types.Config) *types.SFTPGoUser {
	return &types.SFTPGoUser{
		Status:      1,
		Username:    config.SFTPGoAuthdUsername,
		HomeDir:     makeLocalHomePath(config),
		Permissions: makePermissions(config),
		Filters:     makeFilters(config),
		FileSystem:  makeFileSystemForPasswordAuth(config),
	}
}

func MakeSFTPGoUserForPublicKeyAuth(config *types.Config) *types.SFTPGoUser {
	return &types.SFTPGoUser{
		Status:      1,
		Username:    config.SFTPGoAuthdUsername,
		HomeDir:     makeLocalHomePath(config),
		Permissions: makePermissions(config),
		Filters:     makeFilters(config),
		FileSystem:  makeFileSystemForPublicKeyAuth(config),
	}
}
