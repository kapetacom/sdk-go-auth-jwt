// Copyright 2023 Kapeta Inc.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/avast/retry-go/v4"
	"github.com/golang-jwt/jwt/v5"
	sdkconfig "github.com/kapetacom/sdk-go-config/providers"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

const PORT_TYPE = "http"
const PATH_KAPETA_AUTHENTICATION = "/.kapeta/authentication.json"
const PATH_WELL_KNOWN_JWKS = "/.well-known/jwks.json"

type KapetaAuthenticationMetadata struct {
	Type     string `json:"type"`
	Jwks     string `json:"jwks"`
	Issuer   string `json:"issuer"`
	Audience any    `json:"audience"`
}

// JWTMiddlewareFromConfig is a middleware that gets metadata from the specific resource indicating where
// to find a keystore and uses the public key from the keystore to verify the JWT token.
// The middleware can be disabled by setting the environment variable KAPETA_DISABLE_JWT to true.
// The middleware can be overridden by setting the environment variable KAPETA_OVERRIDE_JWT to the URL of the keystore.
func JWTMiddlewareFromConfig(resourceName string, provider sdkconfig.ConfigProvider) []echo.MiddlewareFunc {
	if os.Getenv("KAPETA_DISABLE_JWT") == "true" {
		return []echo.MiddlewareFunc{}
	}
	if jwtUTL := os.Getenv("KAPETA_OVERRIDE_JWT"); jwtUTL != "" {
		return jWTMiddleware(jwtUTL)
	}
	baseUrl, err := provider.GetServiceAddress(resourceName, PORT_TYPE)
	if err != nil {
		panic(err)
	}
	if baseUrl == "" {
		panic(fmt.Errorf("unable to find the service address for the resource: %v", resourceName))
	}
	baseUrl = strings.TrimSuffix(baseUrl, "/")
	authURL := baseUrl + PATH_KAPETA_AUTHENTICATION

	responseBody, err := fetchMetadataWithRetry(authURL)
	if err != nil {
		panic(err)
	}

	var metadata KapetaAuthenticationMetadata
	if err := json.NewDecoder(responseBody).Decode(&metadata); err != nil {
		panic(fmt.Errorf("unable to unmarshal the authentication metadata from Kapeta. Error: %v", err.Error()))
	}
	jwksURL := baseUrl + metadata.Jwks
	return jWTMiddleware(jwksURL)
}

// jWTMiddleware is a middleware that checks for a valid JWT token in the Authorization header
// and sets the user in the context.
// The JWT token is verified using the public key from the specified location.
// Example:
//
//	 g := e.Group("/api/v1")
//		g.Use(jwtauth.jWTMiddleware("https://identity/.well-known/jwks.json")...)
//		g.GET("/test", func(c echo.Context) error {
//			return c.JSON(200, "test")
//		})
func jWTMiddleware(jwtPublicKeyLocation string, userDefinedConfig ...echojwt.Config) []echo.MiddlewareFunc {
	var config echojwt.Config

	if len(userDefinedConfig) > 0 {
		config = userDefinedConfig[0]
	} else {
		config = echojwt.Config{
			// specify the function that returns the public key that will be used to verify the JWT
			KeyFunc: fetchKey(jwtPublicKeyLocation),
		}
	}
	// Create a restricted group of routes that requires a valid JWT
	return []echo.MiddlewareFunc{echojwt.WithConfig(config), restricted()}
}

func restricted() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get the "user" from the context, the user is set by the JWT middleware and is a *jwt.Token
			user := c.Get("user")
			if user == nil {
				return echo.ErrUnauthorized
			}
			token := user.(*jwt.Token)

			if !token.Valid {
				return echo.ErrUnauthorized
			}
			c.Set("jwt", token)
			c.Set("jwt_raw", token.Raw)
			if next == nil {
				return nil
			}
			if err := next(c); err != nil {
				c.Error(err)
				return err
			}
			return nil
		}
	}
}

func getPublicToken(url string) (jwk.Set, error) {
	if strings.HasPrefix(url, "file://") {
		buf, err := os.ReadFile(strings.TrimPrefix(url, "file://"))
		if err != nil {
			return nil, fmt.Errorf("unable to read the key file. Error: %v", err.Error())
		}
		keySet, err := jwk.Parse(buf)
		if err != nil {
			return nil, fmt.Errorf("unable to parse the key file. Error: %v", err.Error())
		}
		return keySet, nil
	}
	// Note: We download the keyset every time the restricted route is accessed.
	keySet, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch the keyset from %v. Error: %v", url, err.Error())
	}
	return keySet, nil
}

// fetchKey is a function that returns a jwt.Keyfunc that can be used to verify the JWT
func fetchKey(url string) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		keySet, err := getPublicToken(url)
		if err != nil {
			return nil, err
		}
		kid := token.Header["kid"]

		keyID, ok := kid.(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have a key ID in the kid field")
		}
		key, found := keySet.LookupKeyID(keyID)

		if !found {
			return nil, fmt.Errorf("unable to find key %v", keyID)
		}

		var pubkey interface{}
		if err := key.Raw(&pubkey); err != nil {
			return nil, fmt.Errorf("unable to get the public key. Error: %s", err.Error())
		}
		return pubkey, nil
	}
}

func fetchMetadataWithRetry(authURL string) (io.ReadCloser, error) {
	body, err := retry.DoWithData(
		func() (io.ReadCloser, error) {
			println(fmt.Sprintf("Attempting to fetch Kapeta authentication metadata from url: %v", authURL))
			return fetchMetadata(authURL)
		},
	)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// fetchMetadata is a function that fetches and returns Kapeta authentication metadata from the specified URL.
// The metadata includes the location of the keystore and the issuer of the JWT.
func fetchMetadata(authURL string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create a new request. Error: %v", err.Error())
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to get the authentication metadata from Kapeta. Error: %v", err.Error())
	}

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("invalid response from Kapeta authentication service while getting metadata %d for %v", response.StatusCode, authURL)
	}

	return response.Body, nil
}
