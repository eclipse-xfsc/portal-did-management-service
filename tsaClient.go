package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"io"
	"io/ioutil"
)

func tsaSaveDidConfiguration(requestBody map[string]interface{}, url string) (map[string]interface{}, error) {
	var resp *http.Response
	var responseBody []byte
	method := "POST"
	emptyResponseBody := make(map[string]interface{})

	jsonBody, _ := json.Marshal(requestBody)

	request, err := http.NewRequest(method, url, strings.NewReader(string(jsonBody)))
	request.Header.Set("Content-type", "application/json")	

	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		responseBody, err = ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			var f interface{}
			json.Unmarshal(responseBody, &f)

			m := f.(map[string]interface{})

			return m, nil
		} else {
			err = fmt.Errorf("invalid Status code (%v)", resp.StatusCode)
			return emptyResponseBody, err
		}
	} else {
		return emptyResponseBody, err
	}
}

func tsaGetDidConfiguration(url string) (map[string]interface{}, error) {
	var resp *http.Response
	var responseBody []byte
	method := "GET"
	emptyResponseBody := make(map[string]interface{})

	request, err := http.NewRequest(method, url, strings.NewReader(string("")))
	request.Header.Set("Content-type", "application/json")	

	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		responseBody, err = ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			var f interface{}
			json.Unmarshal(responseBody, &f)

			m := f.(map[string]interface{})

			return m, nil
		} else {
			err = fmt.Errorf("invalid Status code (%v)", resp.StatusCode)
			return emptyResponseBody, err
		}
	} else {
		return emptyResponseBody, err
	}
}