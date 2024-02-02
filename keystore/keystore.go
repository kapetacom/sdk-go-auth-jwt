// Copyright 2023 Kapeta Inc.
// SPDX-License-Identifier: MIT

package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
)

func EnsureFileKeystore(filename string) (jwk.Set, error) {
	fileStat, err := os.Stat(filename)
	if err == nil && fileStat.Mode().IsRegular() {
		content, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		return jwk.Parse([]byte(content))
	}

	raw, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate new ECDSA private key: %s\n", err)
		return nil, err
	}

	key, err := jwk.New(raw)
	if err != nil {
		fmt.Printf("failed to create ECDSA key: %s\n", err)
		return nil, err
	}
	if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
		fmt.Printf("expected jwk.ECDSAPrivateKey, got %T\n", key)
		return nil, err
	}
	buf, err := json.Marshal(key)
	if err != nil {
		fmt.Printf("failed to marshal key into JSON: %s\n", err)
		return nil, err
	}
	err = os.WriteFile(filename, buf, 0644)
	if err != nil {
		fmt.Printf("failed to write key to file: %s\n", err)
		return nil, err
	}
	return jwk.Parse(buf)
}
