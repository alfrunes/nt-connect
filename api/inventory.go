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
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
)

type Attribute struct {
	Key   string `json:"name"`
	Value string `json:"value"`
}

type Inventory struct {
	attributes []Attribute
}

func NewInventory(attrs []Attribute) Inventory {
	sort.SliceStable(attrs, func(i, j int) bool {
		return attrs[i].Key < attrs[j].Key
	})
	var (
		i int
		n int = len(attrs)
	)
	// deduplication
	for i = 1; i < n; i++ {
		if attrs[i-1].Key == attrs[i].Key {
			break
		}
	}
	j := i - 1
	for ; i < n; i++ {
		if attrs[i].Key == attrs[j].Key {
			continue
		} else {
			// swap i, j
			j++
			attrs[i], attrs[j] = attrs[j], attrs[i]
		}
	}
	return Inventory{attributes: attrs[:j+1]}
}

func (inv Inventory) MarshalText() ([]byte, error) {
	var buf bytes.Buffer
	for _, attr := range inv.attributes {
		buf.WriteString(fmt.Sprintf("%s=%s\n", attr.Key, attr.Value))
	}
	return buf.Bytes(), nil
}

func (inv *Inventory) UnmarshalText(b []byte) error {
	attrs := []Attribute{}
	var i int
	for {
		i = bytes.IndexRune(b, '\n')
		if i < 0 {
			if len(b) > 0 {
				i = len(b)
			} else {
				break
			}
		}
		j := i
		if j > 0 && b[j-1] == '\r' {
			// Trim carriage return
			j--
		}
		if j <= 0 {
			// empty line
			b = b[i+1:]
			continue
		}
		var attr Attribute
		delim := bytes.IndexRune(b[:j], '=')
		if delim < 1 {
			return fmt.Errorf("invalid inventory attribute %q", string(b[:j]))
		}
		attr.Key = string(b[:delim])
		attr.Value = string(b[delim+1 : j])
		attrs = append(attrs, attr)
		b = b[i:]
	}
	*inv = NewInventory(attrs)
	return nil
}

func (inv Inventory) Digest() []byte {
	hash := fnv.New64()
	b, _ := inv.MarshalText()
	_, _ = hash.Write(b)
	return hash.Sum(nil)
}

func (inv Inventory) MarshalJSON() ([]byte, error) {
	return json.Marshal(inv.attributes)
}
