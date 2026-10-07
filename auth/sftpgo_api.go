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

// EnsureVirtualFolders ensures all virtual folders exist in SFTPGo.
// For each folder, it checks via GET /api/v2/folders/{name}; if not found, creates it via POST.
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
	// the folder name is a path segment, so it must be escaped
	requestURL := fmt.Sprintf("%s/api/v2/folders/%s", config.SFTPGoAPIBaseURL, url.PathEscape(vfolder.Name))

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to build GET request for folder %q", vfolder.Name)
	}
	req.Header.Set("X-SFTPGO-API-KEY", config.SFTPGoAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "GET /api/v2/folders/%s failed", vfolder.Name)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// folder already exists
		return nil
	}

	if resp.StatusCode != http.StatusNotFound {
		return errors.Errorf("unexpected status %d when checking folder %q", resp.StatusCode, vfolder.Name)
	}

	return createFolder(client, config, vfolder)
}

func createFolder(client *http.Client, config *commons.Config, vfolder *types.SFTPGoVirtualFolder) error {
	folder := types.SFTPGoFolder{
		Name:        vfolder.Name,
		Description: vfolder.Description,
		FileSystem:  vfolder.FileSystem,
	}

	body, err := json.Marshal(folder)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal folder %q", vfolder.Name)
	}

	requestURL := fmt.Sprintf("%s/api/v2/folders", config.SFTPGoAPIBaseURL)
	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return errors.Wrapf(err, "failed to build POST request for folder %q", vfolder.Name)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SFTPGO-API-KEY", config.SFTPGoAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "POST /api/v2/folders failed for folder %q", vfolder.Name)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		errBody, _ := io.ReadAll(resp.Body)
		return errors.Errorf("failed to create folder %q: status %d, body: %s", vfolder.Name, resp.StatusCode, errBody)
	}

	return nil
}
