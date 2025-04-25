package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

func kongListRoutes(address string, routeId string) (map[string]interface{}, error) {
	var resp *http.Response
	var responseBody []byte
	method := "GET"
	var URL = address + "/routes"

	if routeId != "" {
		URL = address + "/routes/" + routeId
	}
	Logger.Error(URL)
	emptyResponseBody := make(map[string]interface{})

	request, err := http.NewRequest(method, URL, strings.NewReader(string("")))

	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		responseBody, err = ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			var f interface{}
			json.Unmarshal(responseBody, &f)

			filteredArray := make([]interface{}, 0)
			m := f.(map[string]interface{})

			if routeId == "" {
				for _, i := range m["data"].([]interface{}) {
					item := i.(map[string]interface{})
					if item["tags"] != nil {
						tags := item["tags"].([]interface{})
						if len(tags) > 1 {
							if tags[1].(string) == "did-management" {
								filteredArray = append(filteredArray, i)
							}
						}
					}
				}
			} else {
				for _, i := range m["tags"].([]interface{}) {
					if i.(string) == "did-management" {
						filteredArray = append(filteredArray, i)
					}
				}
			}

			var returnObject = make(map[string]interface{})
			returnObject["data"] = filteredArray
			return returnObject, nil
		} else {
			err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, extractBody(resp.Body))
			return emptyResponseBody, err
		}
	} else {
		return emptyResponseBody, err
	}
}

func kongListService(address string, serviceId string) (map[string]interface{}, error) {
	var resp *http.Response
	var responseBody []byte
	method := "GET"
	var URL = address + "/services"

	if serviceId != "" {
		URL = address + "/services/" + serviceId
	}

	emptyResponseBody := make(map[string]interface{})

	request, err := http.NewRequest(method, URL, strings.NewReader(string("")))

	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		responseBody, err = ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			var f interface{}
			json.Unmarshal(responseBody, &f)
			switch f.(type) {
			case []interface{}:
				arrayResponseBody := make(map[string]interface{})
				arrayResponseBody["roles"] = f
				return arrayResponseBody, nil
			}

			m := f.(map[string]interface{})

			return m, nil
		} else {
			err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, extractBody(resp.Body))
			return emptyResponseBody, err
		}
	} else {
		return emptyResponseBody, err
	}
}

func kongCreateService(id string, name string, protocol string, host string, path string, port string, address string) error {
	method := "POST"
	URL := address + "/services"

	requestBody := make(map[string]interface{})

	requestBody["id"] = id
	requestBody["name"] = name
	requestBody["protocol"] = protocol
	requestBody["host"] = host

	if path != "" {
		requestBody["path"] = path
	}

	if port != "" {
		port, err := strconv.Atoi(port)
		if err == nil {
			requestBody["port"] = port
		} else {
			return err
		}
	}

	jsonBody, _ := json.Marshal(requestBody)

	request, err := http.NewRequest(method, URL, strings.NewReader(string(jsonBody)))
	request.Header.Set("Content-type", "application/json")

	return processRequest(request, err)
}

func kongCreateRoute(serviceId string, id string, name string, path string, address string) error {
	method := "POST"
	URL := address + "/services/" + serviceId + "/routes"
	Logger.Debug(URL)
	requestBody := make(map[string]interface{})
	requestBody["name"] = id
	requestBody["tags"] = [2]string{name, "did-management"}
	requestBody["paths"] = [1]string{path}
	requestBody["methods"] = [1]string{"GET"}

	Logger.Debug(name)
	Logger.Debug(path)

	jsonBody, _ := json.Marshal(requestBody)
	request, err := http.NewRequest(method, URL, strings.NewReader(string(jsonBody)))
	request.Header.Set("Content-type", "application/json")

	return processRequest(request, err)
}

func kongRequestTransformerExist(routeId string, address string) (bool, error) {
	var resp *http.Response
	method := "GET"
	URL := address + "/routes/" + routeId + "/plugins"
	request, err := http.NewRequest(method, URL, nil)

	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			responsebody := extractBody(resp.Body)
			body := make(map[string]interface{})
			json.Unmarshal([]byte(responsebody), &body)

			if len(body["data"].([]interface{})) == 0 {
				return false, nil
			}
			return true, nil
		} else {
			err = fmt.Errorf("invalid Status code (%v): (%v)", resp.StatusCode, extractBody(resp.Body))
			return false, err
		}
	} else {
		return false, err
	}
}

func kongCreateRequestTransformer(routeId string, filter string, did string, address string) error {
	var resp *http.Response
	method := "POST"
	URL := address + "/routes/" + routeId + "/plugins"

	requestBody := make(map[string]interface{})
	addBody := make(map[string]interface{})
	headerBody := make(map[string]interface{})
	requestBody["name"] = "request-transformer"
	headers := make([]string, 3)
	headers[0] = "X-DID-TRANSIT-ENGINE:" + routeId
	headers[1] = "X-DID-KEY-FILTER:" + filter
	headers[2] = "X-DID-LOCATION:" + did
	addBody["add"] = headerBody
	headerBody["headers"] = headers
	requestBody["config"] = addBody

	o, _ := json.Marshal(requestBody)
	request, err := http.NewRequest(method, URL, bytes.NewBuffer(o))
	request.Header.Set("Content-type", "application/json")

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
}

func kongDeleteService(service string, address string) error {
	method := "DELETE"
	URL := address + "/services/" + service

	request, err := http.NewRequest(method, URL, strings.NewReader(""))

	return processRequest(request, err)
}

func kongDeleteRoute(route string, address string) error {
	method := "DELETE"
	URL := address + "/routes/" + route

	request, err := http.NewRequest(method, URL, strings.NewReader(""))

	return processRequest(request, err)
}
