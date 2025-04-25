package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type RequiredClaims struct {
	Context string   `json:"context"`
	Claims  []string `json:"claims"`
}

type config struct {
	port                                                  int
	baseURL, cryptoAlgo, basePath                         string
	identityProviderOidURL                                string
	tokenRolesPath, tokenContextPath                      string
	requiredClaims                                        []RequiredClaims
	claimMappingURL                                       string
	vaultURL, vaultToken                                  string
	kongAdminApiURL                                       string
	tsaPolicyServiceHost, tsaPolicyServicePort            string
	tsaPolicyServicePath, tsaPolicyServiceProtocol        string
	tsaGetDidConfigurationUrl, tsaSaveDidConfigurationUrl string
	ocmEndpoints                                          []string
	kongServiceId                                         string
}

func getConfig() (config, error) {
	port, found := os.LookupEnv("PORT")
	if !found {
		err := fmt.Errorf("Environemnt variable \"PORT\" not found")
		return config{}, err
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return config{}, err
	}

	baseURL, found := os.LookupEnv("BASE_URL")
	if !found {
		err := fmt.Errorf("Environemnt variable \"BASE_URL\" not found")
		return config{}, err
	}

	tsaPolicyServiceUrl, found := os.LookupEnv("TSA_SERVICE_URL")
	var tsaPolicyServiceHost string
	var tsaPolicyServicePort string
	var tsaPolicyServicePath string
	var tsaPolicyServiceProtocol string
	if !found {
		err := fmt.Errorf("Environemnt variable \"TSA_SERVICE_URL\" not found")
		return config{}, err
	} else {
		url, err := url.Parse(tsaPolicyServiceUrl)
		if err == nil {
			tsaPolicyServiceHost = strings.Split(url.Host, ":")[0]
			tsaPolicyServicePort = url.Port()
			tsaPolicyServicePath = url.Path
			tsaPolicyServiceProtocol = url.Scheme
		} else {
			err := fmt.Errorf("Error Parsing TSA Service URL")
			return config{}, err
		}
	}

	kongServiceId, found := os.LookupEnv("KONG_SERVICE_ID")
	if !found {
		err := fmt.Errorf("Environemnt variable \"KONG_SERVICE_ID\" not found")
		return config{}, err
	}

	cryptoAlgo, found := os.LookupEnv("CRYPTO_ALGO")
	if !found {
		err := fmt.Errorf("Environemnt variable \"CRYPTO_ALGO\" not found")
		return config{}, err
	}

	identityProviderOidURL, found := os.LookupEnv("IDENTITY_PROVIDER_OID_URL")
	if !found {
		err := fmt.Errorf("Environemnt variable \"IDENTITY_PROVIDER_OID_URL\" not found")
		return config{}, err
	}

	tokenRolesPath, found := os.LookupEnv("TOKEN_ROLES_PATH")
	if !found {
		err := fmt.Errorf("Environemnt variable \"TOKEN_ROLES_PATH\" not found")
		return config{}, err
	}
	tokenContextPath, found := os.LookupEnv("TOKEN_CONTEXT_PATH")
	if !found {
		err := fmt.Errorf("Environemnt variable \"TOKEN_CONTEXT_PATH\" not found")
		return config{}, err
	}

	requiredClaimsString, found := os.LookupEnv("REQUIRED_CLAIMS")
	if !found {
		err := fmt.Errorf("Environemnt variable \"REQUIRED_CLAIMS\" not found")
		return config{}, err
	}

	claimMappingURL, found := os.LookupEnv("CLAIM_MAPPING_URL")
	if !found {
		err := fmt.Errorf("Environemnt variable \"CLAIM_MAPPING_URL\" not found")
		return config{}, err
	}

	vaultURL, found := os.LookupEnv("VAULT_URL")
	if !found {
		err := fmt.Errorf("Environemnt variable \"VAULT_URL\" not found")
		return config{}, err
	}
	vaultToken, found := os.LookupEnv("VAULT_TOKEN")
	if !found {
		err := fmt.Errorf("Environemnt variable \"VAULT_TOKEN\" not found")
		return config{}, err
	}

	kongAdminApiURL, found := os.LookupEnv("KONG_ADMIN_API_URL")
	if !found {
		err := fmt.Errorf("Environemnt variable \"KONG_ADMIN_API_URL\" not found")
		return config{}, err
	}

	tsaGetDidConfigurationUrl, found := os.LookupEnv("TSA_GET_DID_CONFIGURATION_URL")
	if !found {
		err := fmt.Errorf("Environemnt variable \"TSA_GET_DID_CONFIGURATION_URL\" not found")
		return config{}, err
	}
	tsaSaveDidConfigurationUrl, found := os.LookupEnv("TSA_SAVE_DID_CONFIGURATION_URL")
	if !found {
		err := fmt.Errorf("Environemnt variable \"TSA_SAVE_DID_CONFIGURATION_URL\" not found")
		return config{}, err
	}

	ocmEndpoints, found := os.LookupEnv("OCM_ENDPOINTS")
	if !found {
		err := fmt.Errorf("Environemnt variable \"OCM_ENDPOINTS\" not found")
		return config{}, err
	}
	ocmEndpointsArray := strings.Split(ocmEndpoints, ",")
	var ocmEditedEndpointsArray []string
	for _, value := range ocmEndpointsArray {
		ocmEditedEndpointsArray = append(ocmEditedEndpointsArray, strings.TrimSpace(value))
	}

	var requiredClaims []RequiredClaims
	err = json.Unmarshal([]byte(requiredClaimsString), &requiredClaims)
	if err != nil {
		err := fmt.Errorf("Environemnt variable \"REQUIRED_CLAIMS\" is invalid")
		return config{}, err
	}

	basePath, found := os.LookupEnv("BASE_PATH")
	if !found {
		err := fmt.Errorf("Environemnt variable \"BASE_PATH\" not found")
		return config{}, err
	}

	config := config{
		port:     portInt,
		basePath: basePath,
		baseURL:  baseURL, cryptoAlgo: cryptoAlgo,
		identityProviderOidURL: identityProviderOidURL,
		tokenRolesPath:         tokenRolesPath,
		tokenContextPath:       tokenContextPath,
		requiredClaims:         requiredClaims,
		claimMappingURL:        claimMappingURL,
		vaultURL:               vaultURL, vaultToken: vaultToken,
		kongAdminApiURL:            kongAdminApiURL,
		tsaGetDidConfigurationUrl:  tsaGetDidConfigurationUrl,
		tsaSaveDidConfigurationUrl: tsaSaveDidConfigurationUrl,
		ocmEndpoints:               ocmEditedEndpointsArray,
		tsaPolicyServiceHost:       tsaPolicyServiceHost,
		tsaPolicyServicePort:       tsaPolicyServicePort,
		tsaPolicyServicePath:       tsaPolicyServicePath,
		tsaPolicyServiceProtocol:   tsaPolicyServiceProtocol,
		kongServiceId:              kongServiceId,
	}

	return config, nil
}
