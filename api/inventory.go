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
	"bufio"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strings"
)

type InventoryValue []string

func (v InventoryValue) MarshalJSON() ([]byte, error) {
	switch len(v) {
	case 0:
		return []byte{'"', '"'}, nil
	case 1:
		return json.Marshal(v[0])
	default:
		return json.Marshal([]string(v))
	}
}

type Inventory map[string]InventoryValue

func NewInventoryFromStream(r io.Reader) (Inventory, error) {
	s := bufio.NewScanner(r)
	inv := make(Inventory)

	for s.Scan() {
		kv := strings.SplitN(s.Text(), "=", 2)
		if len(kv) < 2 {
			continue
		}
		key := kv[0]
		value := kv[1]
		inv[key] = append(inv[key], value)
	}
	return inv, s.Err()
}

func (inv Inventory) Digest() []byte {
	hash := fnv.New64()
	keys := make([]string, 0, len(inv))
	for key := range inv {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range inv[key] {
			_, _ = hash.Write([]byte(fmt.Sprintf("%s=%s\n", key, value)))
		}
	}
	return hash.Sum(nil)
}

func (inv Inventory) MarshalJSON() ([]byte, error) {
	type Schema struct {
		Name  string         `json:"name"`
		Value InventoryValue `json:"value"`
	}
	schema := make([]Schema, 0, len(inv))
	for key := range inv {
		schema = append(schema, Schema{
			Name:  key,
			Value: inv[key],
		})
	}
	sort.Slice(schema, func(i, j int) bool {
		return schema[i].Name < schema[j].Name
	})
	return json.Marshal(schema)
}
