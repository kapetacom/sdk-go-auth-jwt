// Copyright 2023 Kapeta Inc.
// SPDX-License-Identifier: MIT

package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kapetacom/sdk-go-auth-jwt/keystore"
	"github.com/kapetacom/sdk-go-config/providers"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwa"
	ljwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

func TestFetchJWT(t *testing.T) {

	t.Run("should fail to unmarshal nil key", func(t *testing.T) {
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, r.Method, "GET")
			assert.Equal(t, r.URL.Path, "/.well-known/jwks.json")
		}))
		defer svr.Close()
		keyFunc := fetchKey(svr.URL + "/.well-known/jwks.json")
		_, err := keyFunc(nil)
		assert.Error(t, err)
	})

	t.Run("should be able to fetch a token and validate the key id", func(t *testing.T) {
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwkJSON := `{
				"keys": [ 
				  {
					"kty": "RSA",
					"n": "o76AudS2rsCvlz_3D47sFkpuz3NJxgLbXr1cHdmbo9xOMttPMJI97f0rHiSl9stltMi87KIOEEVQWUgMLaWQNaIZThgI1seWDAGRw59AO5sctgM1wPVZYt40fj2Qw4KT7m4RLMsZV1M5NYyXSd1lAAywM4FT25N0RLhkm3u8Hehw2Szj_2lm-rmcbDXzvjeXkodOUszFiOqzqBIS0Bv3c2zj2sytnozaG7aXa14OiUMSwJb4gmBC7I0BjPv5T85CH88VOcFDV51sO9zPJaBQnNBRUWNLh1vQUbkmspIANTzj2sN62cTSoxRhSdnjZQ9E_jraKYEW5oizE9Dtow4EvQ",
					"use": "sig",
					"alg": "RS256",
					"e": "AQAB",
					"kid": "6a8ba5652a7044121d4fedac8f14d14c54e4895b"
				  }
				]
			  }
			  `
			fmt.Fprintf(w, "%v", jwkJSON)
		}))
		defer svr.Close()

		keyFunc := fetchKey(svr.URL)
		publicKey, err := keyFunc(&jwt.Token{Header: map[string]interface{}{"kid": "6a8ba5652a7044121d4fedac8f14d14c54e4895b"}})
		assert.NoError(t, err)
		assert.NotNil(t, publicKey)
	})
}

func TestRestricted(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	t.Run("should return an error if the user is not authenticated", func(t *testing.T) {
		err := restricted()(func(c echo.Context) error {
			return nil
		})(c)
		assert.Error(t, err)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("should set a jwt token on the context if the user is authenticated", func(t *testing.T) {
		c.Set("user", &jwt.Token{Valid: true})
		err := restricted()(func(c echo.Context) error {
			return nil
		})(c)
		assert.NoError(t, err)
		assert.NotNil(t, c.Get("jwt"))
	})

}

func TestJWTMiddleware(t *testing.T) {
	key, _ := keystore.EnsureFileKeystore("keystore.json")
	defer os.Remove("keystore.json")

	// Create a mock HTTP server
	e := echo.New()
	e.Use(jWTMiddleware("keystore.json")...)
	e.GET("/test", func(c echo.Context) error {
		return c.JSON(200, "test")
	})

	// Create a mock HTTP request
	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	token := ljwt.New()

	// Sign the token and generate a JWS message
	signed, err := ljwt.Sign(token, ljwt.WithKey(jwa.RS256, key))
	if err != nil {
		fmt.Printf("failed to generate signed serialized: %s\n", err)
		return
	}

	if err != nil {
		t.Fatalf("jwt.SignedString: %v", err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(signed)))

	// Send the request to the server
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)

	// Check the response status code
	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	// Check the response body
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	if string(body) != "test" {
		t.Errorf("expected body to be \"test\", got %s", string(body))
	}

}

func TestCallingMetadataEndpoint(t *testing.T) {
	t.Run("should call the metadata endpoint", func(t *testing.T) {
		metaDataCalled := false
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.kapeta/authentication.json" {
				metaData := KapetaAuthenticationMetadata{
					Jwks: "/.well-known/jwks.json",
				}
				err := json.NewEncoder(w).Encode(metaData)
				if err != nil {
					panic(fmt.Errorf("unable to marshal the authentication metadata from Kapeta. Error: %v", err.Error()))
				}
				metaDataCalled = true
				return
			}

		}))
		defer svr.Close()

		// Create a new echo instance
		e := echo.New()

		provider := providers.NewKubernetesConfigProvider("blockRef", "systemid", "instanceId", map[string]interface{}{})

		os.Setenv("KAPETA_CONSUMER_SERVICE_RESOURCENAME_HTTP", svr.URL)
		defer os.Unsetenv("KAPETA_CONSUMER_SERVICE_RESOURCENAME_HTTP")
		// Set the resource name and provider
		e.Use(JWTMiddlewareFromConfig("resourceName", provider)...)

		assert.True(t, metaDataCalled)
	})
}

func TestJWTMiddlewareOverrides(t *testing.T) {
	t.Run("should override the middleware", func(t *testing.T) {
		endpointCalled := false
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, r.Method, "GET")
			assert.Equal(t, r.URL.Path, "/.well-known/jwks.json")
			// we were able to override the URL and call the endpoint
			endpointCalled = true
		}))
		defer svr.Close()

		os.Setenv("KAPETA_OVERRIDE_JWT", svr.URL+"/.well-known/jwks.json")
		defer os.Unsetenv("KAPETA_OVERRIDE_JWT")

		// Create a new echo instance
		e := echo.New()

		// Set the resource name and provider
		mws := JWTMiddlewareFromConfig("resourceName", providers.NewKubernetesConfigProvider("blockRef", "systemid", "instanceId", map[string]interface{}{}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Add("Authorization", "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
		res := httptest.NewRecorder()
		c := e.NewContext(req, res)
		JWTConfigMiddleware := mws[0](func(c echo.Context) error {
			return nil
		})
		_ = JWTConfigMiddleware(c)
		assert.True(t, endpointCalled)
	})
	t.Run("should disable the middleware", func(t *testing.T) {

		os.Setenv("KAPETA_DISABLE_JWT", "true")
		defer os.Unsetenv("KAPETA_DISABLE_JWT")
		// Set the resource name and provider
		mws := JWTMiddlewareFromConfig("resourceName", providers.NewKubernetesConfigProvider("blockRef", "systemid", "instanceId", map[string]interface{}{}))
		assert.Equal(t, 0, len(mws))
	})
}
