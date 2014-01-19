// Copyright (C) 2014 Space Monkey, Inc.

package utils

import (
    "sync"
)

// Future is a type that is essentially the inverse of a channel. With a
// channel, you have multiple senders and one receiver. With a future, you can
// have multiple receivers and one sender. Additionally, a future protects
// against double-sends. Since this is usually used for returning function
// results, we also capture and return error values as well. Use NewFuture
// to initialize.
type Future struct {
    mutex    *sync.Mutex
    cond     *sync.Cond
    received bool
    val      interface{}
    err      error
}

// NewFuture returns an initialized and ready Future.
func NewFuture() *Future {
    mutex := &sync.Mutex{}
    return &Future{
        mutex:    mutex,
        cond:     sync.NewCond(mutex),
        received: false,
        val:      nil,
        err:      nil,
    }
}

// Get blocks until the Future has a value set.
func (self *Future) Get() (interface{}, error) {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    for {
        if self.received {
            return self.val, self.err
        }
        self.cond.Wait()
    }
}

// Fired returns whether or not a value has been set. If Fired is true, Get
// won't block.
func (self *Future) Fired() bool {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    return self.received
}

// Set provides the value to present and future Get calls. If Set has already
// been called, this is a no-op.
func (self *Future) Set(val interface{}, err error) {
    self.mutex.Lock()
    defer self.mutex.Unlock()
    if self.received {
        return
    }
    self.received = true
    self.val = val
    self.err = err
    self.cond.Broadcast()
}
