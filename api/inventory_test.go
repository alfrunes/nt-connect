// Copyright 2023 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.

package api

import (
	"bytes"
	"io"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
)

func TestInventory(t *testing.T) {
	t.Run("decode from stream", func(t *testing.T) {
		input := []byte(`
foo=bar
bar=baz
bar=foo
baz=
`)
		inv, err := NewInventoryFromStream(bytes.NewReader(input))
		assert.NoError(t, err)
		expected := Inventory{
			"foo": InventoryValue{"bar"},
			"bar": InventoryValue{"baz", "foo"},
			"baz": InventoryValue{""},
		}
		assert.Equal(t, expected, inv)
		assert.Equal(t, expected.Digest(), inv.Digest())
		js, _ := inv.MarshalJSON()
		assert.JSONEq(t, `[
{"name":"bar","value":["baz","foo"]},
{"name":"baz","value":""},
{"name":"foo","value":"bar"}]`, string(js))
	})
	t.Run("decode empty stream", func(t *testing.T) {
		inv, err := NewInventoryFromStream(bytes.NewReader([]byte{}))
		assert.NoError(t, err)
		assert.Equal(t, Inventory{}, inv)
		assert.Equal(t, Inventory{}.Digest(), inv.Digest())
	})
	t.Run("error/unexpected EOF", func(t *testing.T) {
		_, err := NewInventoryFromStream(iotest.ErrReader(io.ErrUnexpectedEOF))
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}
