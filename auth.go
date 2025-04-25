package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/yalp/jsonpath"
)

func GetToken(request *http.Request, identityProviderOidURL string) (jwt.Token, error) {
	if request.Header["Authorization"] == nil {
		err := fmt.Errorf("AUTHORIZATION header is missing.")
		Logger.Error(err)

		return jwt.Token{}, err
	}

	var tokenString string
	if len(strings.Fields(request.Header["Authorization"][0])) == 2 {
		tokenString = strings.Fields(request.Header["Authorization"][0])[1]
	} else {
		tokenString = request.Header["Authorization"][0]
	}

	token, err := parseToken(tokenString, identityProviderOidURL)
	if err != nil || !token.Valid {
		Logger.Error("Invalid token. " + err.Error())
		err = fmt.Errorf("Invalid token")
		return token, err
	}

	return token, nil
}

func GetUnverifiedToken(request *http.Request, identityProviderOidURL string) (jwt.Token, error) {
	if request.Header["Authorization"] == nil {
		err := fmt.Errorf("AUTHORIZATION header is missing.")
		Logger.Error(err)

		return jwt.Token{}, err
	}

	var tokenString string
	if len(strings.Fields(request.Header["Authorization"][0])) == 2 {
		tokenString = strings.Fields(request.Header["Authorization"][0])[1]
	} else {
		tokenString = request.Header["Authorization"][0]
	}

	token, _ := parseToken(tokenString, identityProviderOidURL)

	return token, nil
}

func VerifyToken(request *http.Request, identityProviderOidURL string) error {
	if request.Header["Authorization"] == nil {
		err := fmt.Errorf("AUTHORIZATION header is missing.")
		Logger.Error(err)

		return err
	}

	var tokenString string
	if len(strings.Fields(request.Header["Authorization"][0])) == 2 {
		tokenString = strings.Fields(request.Header["Authorization"][0])[1]
	} else {
		tokenString = request.Header["Authorization"][0]
	}

	token, err := parseToken(tokenString, identityProviderOidURL)
	if err != nil || !token.Valid {
		Logger.Error("Invalid token. " + err.Error())
		err = fmt.Errorf("Invalid token")
		return err
	}

	return nil
}

func Authorize(request *http.Request, identityProviderOidURL string, claimMappingURL string, tokenRolesPath string, tokenContextPath string, requiredClaims []RequiredClaims) error {
	if request.Header["Authorization"] == nil {
		err := fmt.Errorf("AUTHORIZATION header is missing.")
		Logger.Error(err)

		return err
	}

	var tokenString string
	if len(strings.Fields(request.Header["Authorization"][0])) == 2 {
		tokenString = strings.Fields(request.Header["Authorization"][0])[1]
	} else {
		tokenString = request.Header["Authorization"][0]
	}

	token, err := parseToken(tokenString, identityProviderOidURL)
	if err != nil || !token.Valid {
		Logger.Error("Invalid token. " + err.Error())
		err = fmt.Errorf("Invalid token")
		return err
	}

	// Check for required claims
	if len(requiredClaims) == 0 {
		return nil
	}

	// Get token's roles
	tokenPayload, _ := json.Marshal(token.Claims.(jwt.MapClaims))
	var tokenData interface{}
	err = json.Unmarshal(tokenPayload, &tokenData)
	roles, err := jsonpath.Read(tokenData, tokenRolesPath)
	if roles == nil {
		err = fmt.Errorf("Invalid or missing roles in token.")
		return err
	}
	var rolesArray []string
	for _, role := range roles.([]interface{}) {
		rolesArray = append(rolesArray, role.(string))
	}

	// Get token's context
	tokenContext, err := jsonpath.Read(tokenData, tokenContextPath)
	if tokenContext == nil {
		err = fmt.Errorf("Missing context in token.")
		return err
	}

	// Get required claims
	var requiredContextClaims []string
	invalidContext := true
	for _, requiredClaim := range requiredClaims {
		if requiredClaim.Context == tokenContext.(string) || requiredClaim.Context == "*" {
			invalidContext = false
			for _, claim := range requiredClaim.Claims {
				requiredContextClaims = append(requiredContextClaims, claim)
			}
		}
	}
	if invalidContext {
		err = fmt.Errorf("Invalid context in token.")
		return err
	}

	if claimMappingURL != "" {
		// Get token claims
		var resp *http.Response
		var responseBody []byte
		method := "GET"
		URL := claimMappingURL

		claimMappingrequest, err := http.NewRequest(method, URL, strings.NewReader(string("")))
		claimMappingrequest.Header.Set("Authorization", "Bearer "+token.Raw)

		resp, err = http.DefaultClient.Do(claimMappingrequest)
		if err == nil {
			responseBody, err = ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
				var f interface{}
				json.Unmarshal(responseBody, &f)
				for _, requiredClaim := range requiredContextClaims {
					claimMissing := true
					for _, claimObject := range f.([]interface{}) {
						claims := claimObject.(map[string]interface{})["claims"].([]interface{})
						for _, claim := range claims {
							if requiredClaim == claim.(map[string]interface{})["Claim"].(string) {
								claimMissing = false
							}
						}
					}
					if claimMissing {
						err = fmt.Errorf("Missing claim \"" + requiredClaim + "\"")
						return err
					}
				}

				return nil
			} else {
				err = fmt.Errorf("invalid Status code (%v)", resp.StatusCode)
				return err
			}
		} else {
			return err
		} 
    } else {
		return nil
	}
}

func parseToken(tokenString string, identityProviderOidURL string) (jwt.Token, error) {
	tkn, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		key, err := getTokenKey(token, identityProviderOidURL)
		keyString, _ := json.Marshal(key)

		jwk := map[string]string{}
		json.Unmarshal([]byte(keyString), &jwk)

		if jwk["kty"] != "RSA" {
			err = fmt.Errorf("invalid key type: (%v)", jwk["kty"])
			return "", err
		}
		nb, err := base64.RawURLEncoding.DecodeString(jwk["n"])
		if err != nil {
			err = fmt.Errorf("Error base64 decoding key")
			return "", err
		}
		e := 0
		if jwk["e"] == "AQAB" || jwk["e"] == "AAEAAQ" {
			e = 65537
		} else {
			err = fmt.Errorf("Key format error")
			return "", err
		}
		pk := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: e,
		}
		der, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			err = fmt.Errorf("Key format error")
			return "", err
		}
		block := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: der,
		}
		var out bytes.Buffer
		pem.Encode(&out, block)

		keyOrig, err := jwt.ParseRSAPublicKeyFromPEM(out.Bytes())
		if err != nil {
			panic("failed to parse DER encoded public key: " + err.Error())
		}

		return keyOrig, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			err = fmt.Errorf("Error invalid token signature")
			return *tkn, err
		}
		err = fmt.Errorf("Error parsing token")
		return *tkn, err
	}

	return *tkn, nil
}

func getTokenKey(token *jwt.Token, identityProviderOidURL string) (map[string]interface{}, error) {
	emptyResponse := make(map[string]interface{})

	allKeys, err := getAllKeys(identityProviderOidURL)
	if err != nil {
		return emptyResponse, err
	}

	for _, key := range allKeys["keys"].([]interface{}) {
		keyObject := key.(map[string]interface{})
		if keyObject["kid"] == token.Header["kid"] {
			return keyObject, nil
		}
	}

	err = fmt.Errorf("Token key not found")
	return emptyResponse, err
}

func getAllKeys(identityProviderOidURL string) (map[string]interface{}, error) {
	var resp *http.Response
	method := "GET"
	emptyResponse := make(map[string]interface{})
	wellKnownURL := identityProviderOidURL + "/.well-known/openid-configuration"

	request, err := http.NewRequest(method, wellKnownURL, strings.NewReader(""))
	resp, err = http.DefaultClient.Do(request)
	if err == nil {
		if resp.StatusCode == 200 {
			responseBody, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
			defer resp.Body.Close()
			var f interface{}
			json.Unmarshal(responseBody, &f)

			method = "GET"
			certsURL := f.(map[string]interface{})["jwks_uri"]
			request, err := http.NewRequest(method, certsURL.(string), strings.NewReader(""))

			resp, err = http.DefaultClient.Do(request)
			if err == nil {
				if resp.StatusCode == 200 {
					responseBody, err = ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
					defer resp.Body.Close()
					var f interface{}
					json.Unmarshal(responseBody, &f)

					return f.(map[string]interface{}), nil
				} else {
					err = fmt.Errorf("invalid Status code (%v)", resp.StatusCode)
					return emptyResponse, err
				}
			} else {
				return emptyResponse, err
			}
		} else {
			err = fmt.Errorf("invalid Status code (%v)", resp.StatusCode)
			return emptyResponse, err
		}
	} else {
		return emptyResponse, err
	}
}
