// Copyright (C) 2014 Space Monkey, Inc.
// +build cgo

package openssl

// #cgo pkg-config: openssl
// #cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN
import "C"
