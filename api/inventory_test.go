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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInventory(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		t.Parallel()
		var inv Inventory
		txt := `foo=bar
foo=bar
foo=bar
testing=test
testing=testing
testing=testing
testing=testing
testing=testing
foo=bar
key=value
key=value
` + "key=value\r"
		err := inv.UnmarshalText([]byte(txt))
		assert.NoError(t, err)
		assert.Equal(t, NewInventory([]Attribute{{
			Key: "foo", Value: "bar",
		}, {
			Key: "key", Value: "value",
		}, {
			Key: "testing", Value: "test",
		}}), inv)
		b, _ := inv.MarshalJSON()
		assert.JSONEq(t, `[
  {"name":"foo","value":"bar"},
  {"name":"key","value":"value"},
  {"name":"testing","value":"test"}
]`, string(b))
	})
	t.Run("marshal/unmarshal", func(t *testing.T) {
		t.Parallel()
		inv := NewInventory([]Attribute{{
			Key:   "testing",
			Value: "testing",
		}, {
			Key:   "foo",
			Value: "bar",
		}, {
			Key:   "testing",
			Value: "testing",
		}, {
			Key:   "testing",
			Value: "testing",
		}, {
			Key:   "testing",
			Value: "testing",
		}, {
			Key:   "foo",
			Value: "bar",
		}, {
			Key:   "foo",
			Value: "bar",
		}})
		b, err := inv.MarshalText()
		assert.NoError(t, err)
		assert.Equal(t, "foo=bar\ntesting=testing\n", string(b))
		var fromText Inventory
		err = fromText.UnmarshalText(b)
		assert.NoError(t, err)
		assert.Equal(t, inv, fromText)
		assert.Equal(t, inv.Digest(), fromText.Digest(), "attribute digest mismatch")
	})

	t.Run("unmarshall/error/no_value", func(t *testing.T) {
		t.Parallel()
		var inv Inventory
		txt := `foobar`
		err := inv.UnmarshalText([]byte(txt))
		assert.EqualError(t, err, `invalid inventory attribute "foobar"`)
	})
}
