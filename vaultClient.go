package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

func VaultGetKey(enginePath string, keyName string, address string, token string) ([]interface{}, error) {
	var resp *http.Response
	var responseBody []byte
	method := "GET"
	emptyResponseBody := make([]interface{}, 0)

	URL := address + "/v1/" + enginePath + "/keys/" + keyName

	request, err := http.NewRequest(method, URL, strings.NewReader(string("")))
	request.Header.Set("X-Vault-Token", token)

	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		responseBody, err = ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			var f interface{}
			var m = make([]interface{}, 0)
			json.Unmarshal(responseBody, &f)
			data := f.(map[string]interface{})["data"]
			keys := data.(map[string]interface{})["keys"]
			for i, v := range keys.(map[string]interface{}) {
				v.(map[string]interface{})["type"] = v.(map[string]interface{})["name"]
				v.(map[string]interface{})["name"] = keyName
				v.(map[string]interface{})["version"] = i
				m = append(m, v)
			}
			return m, nil
		} else {
			err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, extractBody(resp.Body))
			return emptyResponseBody, err
		}
	} else {
		return emptyResponseBody, err
	}
}

func VaultListKeys(enginePath string, address string, token string) ([]string, error) {
	var resp *http.Response
	var responseBody []byte
	method := "LIST"
	URL := address + "/v1/" + enginePath + "/keys"

	request, err := http.NewRequest(method, URL, strings.NewReader(string("")))
	request.Header.Set("X-Vault-Token", token)

	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		responseBody, err = ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			var f interface{}
			json.Unmarshal(responseBody, &f)
			var list = make([]string, 0)
			data := f.(map[string]interface{})["data"]
			keys := data.(map[string]interface{})["keys"]

			for _, v := range keys.([]interface{}) {
				list = append(list, v.(string))
			}
			//m := f.(map[string]interface{})

			return list, nil
		} else {
			err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, extractBody(resp.Body))
			return nil, err
		}
	} else {
		return nil, err
	}
}

func VaultEngineExists(enginePath string, address string, token string) (bool, error) {
	client, err := vaultGetClient(address, token)
	if err != nil {
		err = fmt.Errorf("unable to create vault client: %v", err)
		return false, err
	}

	mo, err := client.Sys().ListMounts()

	if err != nil {
		err = fmt.Errorf("unable to find engine: %v", err)
		return false, err
	}

	for k, _ := range mo {
		if k == enginePath+"/" {
			return true, nil
		}
	}

	return false, nil
}

func VaultCreateEngine(enginePath string, address string, token string) error {
	client, err := vaultGetClient(address, token)
	if err != nil {
		err = fmt.Errorf("unable to create vault client: %v", err)
		return err
	}

	// Enable engine
	mi := vault.MountInput{}
	mi.Type = "transit"
	mi.Description = "Auto Generated Engine from DID Management"
	err = client.Sys().Mount(enginePath, &mi)
	if err != nil {
		err = fmt.Errorf("unable to enable engine: %v", err)
		return err
	}

	return nil
}

func VaultCreateKey(enginePath string, keyName string, cryptoAlgo string, address string, token string) error {
	var resp *http.Response
	method := "POST"

	body := make(map[string]interface{})
	body["type"] = cryptoAlgo
	body["derived"] = false
	body["exportable"] = false
	jsonBody, _ := json.Marshal(body)

	createURL := address + "/v1/" + enginePath + "/keys/" + keyName

	request, err := http.NewRequest(method, createURL, strings.NewReader(string(jsonBody)))
	request.Header.Set("Content-type", "application/json")
	request.Header.Set("X-Vault-Token", token)

	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			configURL := address + "/v1/" + enginePath + "/keys/" + keyName + "/config"
			configBody := make(map[string]interface{})
			configBody["deletion_allowed"] = true
			configJsonBody, _ := json.Marshal(configBody)

			request, err := http.NewRequest(method, configURL, strings.NewReader(string(configJsonBody)))
			request.Header.Set("Content-type", "application/json")
			request.Header.Set("X-Vault-Token", token)

			resp, err = http.DefaultClient.Do(request)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
					return nil
				} else {
					err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, extractBody(resp.Body))
					return err
				}
			} else {
				return err
			}
		} else {
			err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, extractBody(resp.Body))
			return err
		}
	} else {
		return err
	}
}

func VaultDeleteEngine(enginePath string, address string, token string) error {
	client, err := vaultGetClient(address, token)
	if err != nil {
		err = fmt.Errorf("unable to create vault client: %v", err)
		return err
	}

	// Disable engine
	err = client.Sys().Unmount(enginePath)
	if err != nil {
		err = fmt.Errorf("unable to disable engine: %v", err)
		return err
	}

	return nil
}

func VaultDeleteKey(enginePath string, keyName string, address string, token string) error {
	method := "DELETE"

	URL := address + "/v1/" + enginePath + "/keys/" + keyName

	request, err := http.NewRequest(method, URL, strings.NewReader(string("")))
	request.Header.Set("X-Vault-Token", token)

	return processRequest(request, err)
}

func VaultRotateKey(enginePath string, keyName string, address string, token string) error {
	method := "POST"

	URL := address + "/v1/" + enginePath + "/keys/" + keyName + "/rotate"

	request, err := http.NewRequest(method, URL, strings.NewReader(string("")))
	request.Header.Set("X-Vault-Token", token)

	return processRequest(request, err)
}

func vaultGetClient(address string, token string) (*vault.Client, error) {
	config := vault.DefaultConfig()

	config.Address = address

	client, err := vault.NewClient(config)
	if err != nil {
		err = fmt.Errorf("unable to initialize Vault client: %v", err)
		return &vault.Client{}, err
	}

	client.SetToken(token)

	return client, nil
}
