package auth

import (
	"fmt"
	"path"

	"github.com/cyverse/sftpgo-auth-irods/commons"
	"github.com/cyverse/sftpgo-auth-irods/types"
)

const (
	localFsProvider int = 0
	iRODSFsProvider int = 6
)

func makeLocalUserPath(config *commons.Config, sftpgoUsername string) string {
	return path.Join(config.SFTPGoHomeDir, sftpgoUsername)
}

func makeLocalUserSubPath(config *commons.Config, sftpgoUsername string, name string) string {
	return path.Join(config.SFTPGoHomeDir, sftpgoUsername, name)
}

func makePermissions(config *commons.Config, mountPaths []types.MountPath) map[string][]string {
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
	}
}

func makeLocalFileSystem() *types.SFTPGoFileSystem {
	return &types.SFTPGoFileSystem{
		Provider: localFsProvider,
	}
}

func makeFileSystem(config *commons.Config, collectionPath string) *types.SFTPGoFileSystem {
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

func makeVirtualFolders(config *commons.Config, sftpgoUsername string, mountPaths []types.MountPath) []types.SFTPGoVirtualFolder {
	vfolders := []types.SFTPGoVirtualFolder{}
	for _, mountPath := range mountPaths {
		vfolder := types.SFTPGoVirtualFolder{
			Name:        mountPath.Name,
			Description: mountPath.Description,
			MappedPath:  makeLocalUserSubPath(config, sftpgoUsername, mountPath.DirName),
			VirtualPath: fmt.Sprintf("/%s", mountPath.DirName),
			FileSystem:  makeFileSystem(config, mountPath.CollectionPath),
		}

		vfolders = append(vfolders, vfolder)
	}

	return vfolders
}

func MakeSFTPGoUser(config *commons.Config, sftpgoUsername string, mountPaths []types.MountPath) *types.SFTPGoUser {
	return &types.SFTPGoUser{
		Status:         1,
		Username:       sftpgoUsername,
		HomeDir:        makeLocalUserPath(config, sftpgoUsername),
		VirtualFolders: makeVirtualFolders(config, sftpgoUsername, mountPaths),
		Permissions:    makePermissions(config, mountPaths),
		Filters:        makeFilters(config),
		FileSystem:     makeLocalFileSystem(),
	}
}
