package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
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
		err := Restricted()(func(c echo.Context) error {
			return nil
		})(c)
		assert.Error(t, err)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("should set a jwt token on the context if the user is authenticated", func(t *testing.T) {
		c.Set("user", &jwt.Token{Valid: true})
		err := Restricted()(func(c echo.Context) error {
			return nil
		})(c)
		assert.NoError(t, err)
		assert.NotNil(t, c.Get("jwt"))
	})

}
