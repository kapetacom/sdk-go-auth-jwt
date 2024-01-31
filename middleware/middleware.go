package middleware

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

func Restricted() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get the 'user' from the context, the user is set by the JWT middleware and is a *jwt.Token
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
			}
			return nil
		}
	}
}

func getPublicToken(url string) (jwk.Set, error) {
	if strings.HasPrefix(url, "file://") {
		buf, err := os.ReadFile(strings.TrimPrefix(url, "file://"))
		if err != nil {
			log.Println("Unable to read the key file. Error: ", err.Error())
			return nil, err
		}
		keySet, err := jwk.Parse(buf)
		if err != nil {
			log.Println("Unable to parse the key file. Error: ", err.Error())
			return nil, err
		}
		return keySet, nil
	}
	// Note: We download the keyset every time the restricted route is accessed.
	keySet, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		log.Printf("Unable to fetch the keyset from %v. Error: %v", url, err.Error())
		return nil, err
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

func JWTMiddleware(jwtPublicKeyLocation string, claims jwt.Claims) echo.MiddlewareFunc {
	config := echojwt.Config{
		// specify the function that returns the public key that will be used to verify the JWT
		KeyFunc: fetchKey(jwtPublicKeyLocation),
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return claims
		},
	}
	// Create a restricted group of routes that requires a valid JWT
	return echojwt.WithConfig(config)
}
