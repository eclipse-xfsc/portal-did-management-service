package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func extractBody(reader io.ReadCloser) string {
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		Logger.Fatal(err)
	}
	bodyString := string(bodyBytes)
	return bodyString
}

func createDID(baseURL string, path string) string {
	var did string = strings.Replace(baseURL+path, "/", ":", -1)
	return did
}

func webEncoding(s string) string {
	s = strings.Replace(s, "/", "-", -1)
	s = strings.Replace(s, ":", "-", -1)
	return s
}

func handleErrorResponse(w http.ResponseWriter, err error, message string) {
	Logger.Error(err)
	responseBody := []byte(`{"error": {"message": "` + message + `"}}`)
	var responseJson map[string]interface{}
	w.WriteHeader(409)
	json.Unmarshal(responseBody, &responseJson)
	json.NewEncoder(w).Encode(responseJson)
}

func processRequest(request *http.Request, err error) error {
	resp, err := http.DefaultClient.Do(request)
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
}
