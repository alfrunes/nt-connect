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

package types

import (
	"bytes"
	"fmt"
	"strconv"
	"time"
)

type Duration time.Duration

func (dur *Duration) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if len(b) > 1 && b[0] == '"' && b[len(b)-1] == '"' {
		d, err := time.ParseDuration(string(b[1 : len(b)-1]))
		if err != nil {
			return err
		}
		*dur = Duration(d)
	} else if i := bytes.IndexFunc(b, func(r rune) bool {
		return r <= '9' && r >= '0'
	}); i > 0 {
		sec, err := strconv.ParseUint(string(b[:i]), 10, 32)
		if err != nil {
			return fmt.Errorf("failed to parse duration: %s", err)
		}
		*dur = Duration(time.Second * time.Duration(sec))
	} else {
		return fmt.Errorf("malformed duration value: " +
			"must be string or number of seconds")
	}
	return nil
}
