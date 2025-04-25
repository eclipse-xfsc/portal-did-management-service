package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

func RequestLogger(targetMux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		targetMux.ServeHTTP(w, r)

		if string(r.RequestURI) != "/isAlive" {
			Logger.Infow("",
				zap.String("method", string(r.Method)),
				zap.String("uri", string(r.RequestURI)),
				zap.Duration("duration", time.Since(start)*1000),
			)
		}

	})
}

func startServer(port *int) {
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/config", configGet).Methods("GET")
	router.HandleFunc("/did/ocm", didOcmGet).Methods("GET")

	router.HandleFunc("/did/configuration", didConfigGet).Methods("GET")
	router.HandleFunc("/did/configuration", didConfigCreate).Methods("POST")

	router.HandleFunc("/did/web", listWebs).Methods("GET")
	router.HandleFunc("/did/web", createWeb).Methods("POST")
	router.HandleFunc("/did/web/{id}", deleteWeb).Methods("DELETE")
	router.HandleFunc("/did/web/{id}/key", createKey).Methods("POST")
	router.HandleFunc("/did/web/{id}/key/{name}", deleteKey).Methods("DELETE")
	router.HandleFunc("/did/web/{id}/key/{name}/rotate", rotateKey).Methods("GET")

	router.HandleFunc("/isAlive", isAliveGet).Methods("GET")

	portString := ":" + strconv.Itoa(*port)
	setup()
	log.Fatal(http.ListenAndServe(portString, RequestLogger(router)))
}

func setup() {
	config, _ := getConfig()

	var result, err = kongListService(config.kongAdminApiURL, config.kongServiceId)

	if len(result) != 0 {
		Logger.Debug(result)
		Logger.Debug("Service Found. Skip creation.")
	} else {
		err = kongCreateService(config.kongServiceId, "TSA_DID_Document_Service", config.tsaPolicyServiceProtocol, config.tsaPolicyServiceHost, config.tsaPolicyServicePath, config.tsaPolicyServicePort, config.kongAdminApiURL)
		if err != nil {
			Logger.Error(err)
			log.Fatalf("Can't create KONG Service for TSA ")
		}
	}
}

func configGet(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	configuration := make(map[string]interface{})

	configuration["baseUrl"] = config.baseURL
	crypto := make(map[string]interface{})
	crypto["algo"] = config.cryptoAlgo
	configuration["crypto"] = crypto

	json.NewEncoder(w).Encode(configuration)

	return
}

func didOcmGet(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	var response []interface{}
	for _, value := range config.ocmEndpoints {
		info, err := ocmGetInfo(value)
		if err != nil {
			Logger.Error(err)
			err := "Error fetching OCM info."
			responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
			var responseJson map[string]interface{}
			w.WriteHeader(409)
			json.Unmarshal(responseBody, &responseJson)
			json.NewEncoder(w).Encode(responseJson)

			return
		}

		response = append(response, info)
	}

	json.NewEncoder(w).Encode(response)

	return
}

func didConfigGet(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	response, err := tsaGetDidConfiguration(config.tsaGetDidConfigurationUrl)
	if err != nil {
		Logger.Error(err)
		err := "Error fetching TSA DID configuration."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	json.NewEncoder(w).Encode(response)

	return
}

func didConfigCreate(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	// Authentication check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Authorization check
	err = Authorize(r, config.identityProviderOidURL, config.claimMappingURL, config.tokenRolesPath, config.tokenContextPath, config.requiredClaims)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Get body params
	var payload map[string]interface{}
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response, err := tsaSaveDidConfiguration(payload, config.tsaSaveDidConfigurationUrl)
	if err != nil {
		Logger.Error(err)
		err := "Error saving TSA DID configuration."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	json.NewEncoder(w).Encode(response)

	return
}

func listWebs(w http.ResponseWriter, r *http.Request) {
	// Get config
	config, _ := getConfig()

	w.Header().Set("Content-Type", "application/json")

	// Get webs
	webs, err := kongListRoutes(config.kongAdminApiURL, "")
	if err != nil {
		Logger.Error(err)
		err := "Error creating service."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	var response []interface{} = make([]interface{}, 0)

	for _, web := range webs["data"].([]interface{}) {
		var webObject = make(map[string]interface{})
		webObject["id"] = web.(map[string]interface{})["name"]
		webObject["name"] = web.(map[string]interface{})["tags"].([]interface{})[0]
		webObject["path"] = web.(map[string]interface{})["paths"].([]interface{})[0]

		list, err := VaultListKeys(webObject["id"].(string), config.vaultURL, config.vaultToken)
		if err != nil {
			Logger.Error(err)
			webObject["keys"] = make([]interface{}, 0)
		} else {
			array := make([]interface{}, 0)
			for _, i := range list {
				// Get keys
				key, err := VaultGetKey(webObject["id"].(string), i, config.vaultURL, config.vaultToken)
				if err != nil {
					Logger.Error(err)
					err := "Error creating service."
					responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
					var responseJson map[string]interface{}
					w.WriteHeader(409)
					json.Unmarshal(responseBody, &responseJson)
					json.NewEncoder(w).Encode(responseJson)

					return
				}

				for _, i := range key {
					array = append(array, i)
				}

			}
			webObject["keys"] = array
		}
		response = append(response, webObject)
	}

	json.NewEncoder(w).Encode(response)

	w.WriteHeader(http.StatusOK)

	return
}

func createWeb(w http.ResponseWriter, r *http.Request) {
	// Get body params
	var payload map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name, ok := payload["name"].(string)
	if !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	path, ok := payload["path"].(string)

	if !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if path[0:1] != "/" {
		path = "/" + path
	}

	// Get config
	config, _ := getConfig()

	// Authentication check
	err = VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Authorization check
	err = Authorize(r, config.identityProviderOidURL, config.claimMappingURL, config.tokenRolesPath, config.tokenContextPath, config.requiredClaims)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	w.Header().Set("Content-Type", "application/json")

	id := "did-management." + webEncoding(createDID(config.baseURL, path))

	result, err := VaultEngineExists(id, config.vaultURL, config.vaultToken)

	if err != nil {
		handleErrorResponse(w, err, "Getting Vault Engine failed.")
		return
	}

	if !result {
		// Create engine
		err = VaultCreateEngine(id, config.vaultURL, config.vaultToken)
		if err != nil {
			handleErrorResponse(w, err, "Error creating vault engine.")
			return
		}
	}

	route, err := kongListRoutes(config.kongAdminApiURL, id)

	if err != nil {
		err = kongCreateRoute(config.kongServiceId, id, name, config.basePath+path, config.kongAdminApiURL)
		if err != nil {
			handleErrorResponse(w, err, "Error creating kong route.")
			return
		}
	} else {
		Logger.Debug("Route found")
		Logger.Debug(route)
	}
	// Create route

	transformerExist, err := kongRequestTransformerExist(id, config.kongAdminApiURL)

	if err != nil {
		handleErrorResponse(w, err, "Getting request transformers failed.")
		return
	}

	if !transformerExist {
		// Create route request transformer
		err = kongCreateRequestTransformer(id, "*", createDID(config.baseURL, path), config.kongAdminApiURL)
		if err != nil {
			handleErrorResponse(w, err, "Error creating route request transformer.")
			return
		}
	}

	w.WriteHeader(http.StatusOK)

	return
}

func deleteWeb(w http.ResponseWriter, r *http.Request) {
	// Get query params
	vars := mux.Vars(r)
	id := vars["id"]

	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)
		return
	}

	// Get config
	config, _ := getConfig()

	// Authentication check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Authorization check
	err = Authorize(r, config.identityProviderOidURL, config.claimMappingURL, config.tokenRolesPath, config.tokenContextPath, config.requiredClaims)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	w.Header().Set("Content-Type", "application/json")

	route, err := kongListRoutes(config.kongAdminApiURL, id)

	if err == nil {
		Logger.Debug(route)
		// Delete service
		err = kongDeleteRoute(id, config.kongAdminApiURL)
		if err != nil {
			Logger.Error(err)
			err := "Error deleting service."
			responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
			var responseJson map[string]interface{}
			w.WriteHeader(409)
			json.Unmarshal(responseBody, &responseJson)
			json.NewEncoder(w).Encode(responseJson)

			return
		}
	}

	result, err := VaultEngineExists(id, config.vaultURL, config.vaultToken)

	if err != nil {
		handleErrorResponse(w, err, "Getting Vault Engine failed.")
		return
	}

	if result {
		// Delete engine
		err = VaultDeleteEngine(id, config.vaultURL, config.vaultToken)
		if err != nil {
			Logger.Error(err)
			err := "Error deleting engine."
			responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
			var responseJson map[string]interface{}
			w.WriteHeader(409)
			json.Unmarshal(responseBody, &responseJson)
			json.NewEncoder(w).Encode(responseJson)

			return
		}
	}

	w.WriteHeader(http.StatusOK)

	return
}

func createKey(w http.ResponseWriter, r *http.Request) {
	// Get query params
	vars := mux.Vars(r)
	id := vars["id"]
	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	// Get key's name
	var payload map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	keyName, ok := payload["key"].(string)
	if !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get config
	config, _ := getConfig()

	// Authentication check
	err = VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Authorization check
	err = Authorize(r, config.identityProviderOidURL, config.claimMappingURL, config.tokenRolesPath, config.tokenContextPath, config.requiredClaims)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Create key
	err = VaultCreateKey(id, keyName, config.cryptoAlgo, config.vaultURL, config.vaultToken)
	if err != nil {
		Logger.Error(err)
		err := "Error creating key."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	w.WriteHeader(http.StatusOK)

	return
}

func deleteKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}
	keyName := vars["name"]
	if len(keyName) == 0 {
		err := "Invalid parameter name."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	// Get config
	config, _ := getConfig()

	// Authentication check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Authorization check
	err = Authorize(r, config.identityProviderOidURL, config.claimMappingURL, config.tokenRolesPath, config.tokenContextPath, config.requiredClaims)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Delete key
	err = VaultDeleteKey(id, keyName, config.vaultURL, config.vaultToken)
	if err != nil {
		Logger.Error(err)
		err := "Error deleting key."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	w.WriteHeader(http.StatusOK)

	return
}

func rotateKey(w http.ResponseWriter, r *http.Request) {
	// Get query params
	vars := mux.Vars(r)
	id := vars["id"]

	if len(id) == 0 {
		err := "Invalid parameter id."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}
	keyName := vars["name"]
	if len(keyName) == 0 {
		err := "Invalid parameter name."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	// Get config
	config, _ := getConfig()

	// Authentication check
	err := VerifyToken(r, config.identityProviderOidURL)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	// Authorization check
	err = Authorize(r, config.identityProviderOidURL, config.claimMappingURL, config.tokenRolesPath, config.tokenContextPath, config.requiredClaims)
	if err != nil {
		Logger.Error(err)
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(err.Error())

		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Rotate key
	err = VaultRotateKey(id, keyName, config.vaultURL, config.vaultToken)
	if err != nil {
		Logger.Error(err)
		err := "Error rotating key."
		responseBody := []byte(`{"error": {"message": "` + err + `"}}`)
		var responseJson map[string]interface{}
		w.WriteHeader(409)
		json.Unmarshal(responseBody, &responseJson)
		json.NewEncoder(w).Encode(responseJson)

		return
	}

	w.WriteHeader(http.StatusOK)

	return
}

func isAliveGet(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	return
}
