package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/cyverse/sftpgo-auth-irods/commons"
	"github.com/cyverse/sftpgo-auth-irods/types"
)

const (
	apiRequestTimeout time.Duration = 30 * time.Second
)

// EnsureVirtualFolders ensures all virtual folders exist in SFTPGo with the
// current configuration. For each folder, it updates the folder via
// PUT /api/v2/folders/{name}; if the folder is not found, creates it via POST.
// An existing folder is always updated, because its filesystem config (the
// iRODS password, endpoint, collection path, ...) may have changed since it
// was created, and SFTPGo mounts what is stored, not what the hook returns.
func EnsureVirtualFolders(config *commons.Config, vfolders []types.SFTPGoVirtualFolder) error {
	client := &http.Client{
		Timeout: apiRequestTimeout,
	}

	for i := range vfolders {
		if err := ensureFolder(client, config, &vfolders[i]); err != nil {
			return err
		}
	}
	return nil
}

func ensureFolder(client *http.Client, config *commons.Config, vfolder *types.SFTPGoVirtualFolder) error {
	body, err := makeFolderBody(vfolder)
	if err != nil {
		return err
	}

	status, errBody, err := updateFolder(client, config, vfolder.Name, body)
	if err != nil {
		return err
	}

	switch status {
	case http.StatusOK:
		// folder already exists and is updated
		return nil
	case http.StatusNotFound:
		return createFolder(client, config, vfolder.Name, body)
	default:
		return errors.Errorf("failed to update folder %q: status %d, body: %s", vfolder.Name, status, errBody)
	}
}

func makeFolderBody(vfolder *types.SFTPGoVirtualFolder) ([]byte, error) {
	folder := types.SFTPGoFolder{
		Name:        vfolder.Name,
		Description: vfolder.Description,
		FileSystem:  vfolder.FileSystem,
	}

	body, err := json.Marshal(folder)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal folder %q", vfolder.Name)
	}
	return body, nil
}

// updateFolder sends PUT /api/v2/folders/{name} and returns the status code
// and the response body.
func updateFolder(client *http.Client, config *commons.Config, name string, body []byte) (int, []byte, error) {
	// the folder name is a path segment, so it must be escaped
	requestURL := fmt.Sprintf("%s/api/v2/folders/%s", config.SFTPGoAPIBaseURL, url.PathEscape(name))

	req, err := http.NewRequest(http.MethodPut, requestURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.Wrapf(err, "failed to build PUT request for folder %q", name)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SFTPGO-API-KEY", config.SFTPGoAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, errors.Wrapf(err, "PUT /api/v2/folders/%s failed", name)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}

func createFolder(client *http.Client, config *commons.Config, name string, body []byte) error {
	requestURL := fmt.Sprintf("%s/api/v2/folders", config.SFTPGoAPIBaseURL)
	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return errors.Wrapf(err, "failed to build POST request for folder %q", name)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SFTPGO-API-KEY", config.SFTPGoAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "POST /api/v2/folders failed for folder %q", name)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		errBody, _ := io.ReadAll(resp.Body)
		return errors.Errorf("failed to create folder %q: status %d, body: %s", name, resp.StatusCode, errBody)
	}

	return nil
}
