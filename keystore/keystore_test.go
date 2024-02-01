// Copyright 2023 Kapeta Inc.
// SPDX-License-Identifier: MIT

package keystore

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnsureFileKeystore(t *testing.T) {
	t.Run("should create a new keystore if the file does not exist, and load it if it does", func(t *testing.T) {
		defer os.Remove("keystore.json")

		firstKeystore, err := EnsureFileKeystore("keystore.json")
		assert.NoError(t, err)
		assert.NotNil(t, firstKeystore)

		secondKeystore, err := EnsureFileKeystore("keystore.json")
		assert.NoError(t, err)
		assert.NotNil(t, firstKeystore)
		assert.Equal(t, firstKeystore, secondKeystore)
	})
}
