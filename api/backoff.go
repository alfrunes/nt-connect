// Copyright 2023 Northern.tech AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package api

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

type expBackoff struct {
	Client
	timer           *time.Timer
	nextAttempt     time.Time
	backoffDuration time.Duration
	retries         int
	mu              sync.Mutex
}

const (
	backOffMin         = time.Second
	backoffMax         = time.Hour * 8
	defaultMaxAttempts = 20
)

func ExpBackoff(client Client) BackoffClient {
	return &expBackoff{
		Client: client,
		timer:  time.NewTimer(0),
	}
}

type BackoffClient interface {
	Client
	NextAttempt() (time.Time, int)
}

var _ Client = &expBackoff{}

func (a *expBackoff) incBackoff() {
	a.mu.Lock()
	defer a.mu.Unlock()
	jitter := time.Duration((1 - rand.Float64()/2) * float64(backOffMin))
	if a.backoffDuration > backoffMax {
		a.backoffDuration = backoffMax
	} else {
		a.backoffDuration *= 2
	}
	a.backoffDuration += jitter
	if a.nextAttempt.IsZero() {
		a.nextAttempt = time.Now()
	}
	a.nextAttempt = a.nextAttempt.Add(a.backoffDuration)
	a.timer.Reset(a.backoffDuration)
}

func (a *expBackoff) resetBackoff() {
	a.mu.Lock()
	a.nextAttempt = time.Time{}
	a.timer.Reset(0)
	a.backoffDuration = backOffMin
	a.retries = 0
	a.mu.Unlock()
}

func (a *expBackoff) incAttempt() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retries += 1
	return nil
}

func (a *expBackoff) limit(ctx context.Context) error {
	if err := a.incAttempt(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.timer.C:
		a.incBackoff()
	}
	return nil
}

func (a *expBackoff) NextAttempt() (time.Time, int) {
	return a.nextAttempt, a.retries + 1
}

func (a *expBackoff) Authenticate(ctx context.Context) (*Authz, error) {
	if err := a.limit(ctx); err != nil {
		return nil, err
	}
	authz, err := a.Client.Authenticate(ctx)
	if err == nil {
		a.resetBackoff()
	}
	return authz, err
}

func (a *expBackoff) OpenSocket(ctx context.Context, authz *Authz) (Socket, error) {
	if err := a.limit(ctx); err != nil {
		return nil, err
	}
	sock, err := a.Client.OpenSocket(ctx, authz)
	if err == nil {
		a.resetBackoff()
	}
	return sock, err
}
