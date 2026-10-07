package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/cyverse/sftpgo-auth-irods/commons"
	"github.com/cyverse/sftpgo-auth-irods/types"
)

// EnsureVirtualFolders ensures all virtual folders exist in SFTPGo.
// For each folder, it checks via GET /api/v2/folders/{name}; if not found, creates it via POST.
func EnsureVirtualFolders(config *commons.Config, vfolders []types.SFTPGoVirtualFolder) error {
	client := &http.Client{}

	for i := range vfolders {
		if err := ensureFolder(client, config, &vfolders[i]); err != nil {
			return err
		}
	}
	return nil
}

func ensureFolder(client *http.Client, config *commons.Config, vfolder *types.SFTPGoVirtualFolder) error {
	url := fmt.Sprintf("%s/api/v2/folders/%s", config.SFTPGoAPIBaseURL, vfolder.Name)

	req, err := http.NewRequest(http.MethodGet, url, nil)
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

	url := fmt.Sprintf("%s/api/v2/folders", config.SFTPGoAPIBaseURL)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
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
