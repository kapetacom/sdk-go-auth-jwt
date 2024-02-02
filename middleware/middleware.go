// Copyright 2023 Kapeta Inc.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

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
func JWTMiddlewareFromConfig(resourceName string, provider sdkconfig.ConfigProvider) []echo.MiddlewareFunc {
	baseUrl, err := provider.GetServiceAddress(resourceName, PORT_TYPE)
	if err != nil {
		panic(fmt.Errorf("unable to find the service address for the resource: %v", resourceName))
	}
	if baseUrl == "" {
		panic(fmt.Errorf("unable to find the service address for the resource: %v", resourceName))
	}
	baseUrl = strings.TrimSuffix(baseUrl, "/")
	authURL := baseUrl + PATH_KAPETA_AUTHENTICATION

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		panic(fmt.Errorf("unable to create a new request. Error: %v", err.Error()))
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		panic(fmt.Errorf("unable to get the authentication metadata from Kapeta. Error: %v", err.Error()))
	}

	if response.StatusCode != 200 {
		panic(fmt.Errorf("invalid response from Kapeta authentication service: %d", response.StatusCode))
	}

	var metadata KapetaAuthenticationMetadata
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		panic(fmt.Errorf("unable to unmarshal the authentication metadata from Kapeta. Error: %v", err.Error()))
	}
	return jWTMiddleware(baseUrl + metadata.Jwks)
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

		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have a key ID in the kid field")
		}

		key, found := keySet.LookupKeyID(keyID)

		if !found {
			return nil, fmt.Errorf("unable to find key %q", keyID)
		}

		var pubkey interface{}
		if err := key.Raw(&pubkey); err != nil {
			return nil, fmt.Errorf("unable to get the public key. Error: %s", err.Error())
		}
		return pubkey, nil
	}
}
