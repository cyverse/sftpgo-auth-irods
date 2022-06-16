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

func makeLocalUserPath(sftpgoUsername string) string {
	return path.Join(homeDirPrefix, sftpgoUsername)
}

func makeLocalUserSubPath(sftpgoUsername string, name string) string {
	return path.Join(homeDirPrefix, sftpgoUsername, name)
}

func makePermissions(config *types.Config, mountPaths []types.MountPath) map[string][]string {
	permissions := make(map[string][]string)
	permissions["/"] = []string{"list"}

	for _, mountPath := range mountPaths {
		p := fmt.Sprintf("/%s", mountPath.DirName)
		permissions[p] = []string{"*"}
	}

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

func makeVirtualFolders(config *types.Config, sftpgoUsername string, mountPaths []types.MountPath) []types.SFTPGoVirtualFolder {
	vfolders := []types.SFTPGoVirtualFolder{}
	for _, mountPath := range mountPaths {
		vfolder := types.SFTPGoVirtualFolder{
			Name:        mountPath.Name,
			Description: mountPath.Description,
			MappedPath:  makeLocalUserSubPath(sftpgoUsername, mountPath.DirName),
			VirtualPath: fmt.Sprintf("/%s", mountPath.DirName),
			FileSystem:  makeFileSystem(config, mountPath.CollectionPath),
		}

		vfolders = append(vfolders, vfolder)
	}

	return vfolders
}

func MakeSFTPGoUser(config *types.Config, sftpgoUsername string, mountPaths []types.MountPath) *types.SFTPGoUser {
	return &types.SFTPGoUser{
		Status:         1,
		Username:       sftpgoUsername,
		HomeDir:        makeLocalUserPath(sftpgoUsername),
		VirtualFolders: makeVirtualFolders(config, sftpgoUsername, mountPaths),
		Permissions:    makePermissions(config, mountPaths),
		Filters:        makeFilters(config),
		FileSystem:     makeLocalFileSystem(),
	}
}
