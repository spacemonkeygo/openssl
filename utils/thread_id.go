// Copyright (C) 2014 Space Monkey, Inc.

// Package utils provides some small things that implementation of the OpenSSL
// wrapper library needed.
package utils

import (
    "unsafe"
)

// ThreadId returns the current runtime's thread id. Thanks to Gustavo Niemeyer
// for this. https://github.com/niemeyer/qml/blob/master/tref/tref.go
func ThreadId() unsafe.Pointer
