// Copyright (C) 2014 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build cgo

package openssl

/*
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "openssl/evp.h"

// Cast d to uintptr to avoid costly cgoCheckPointer checks.
int _avoid_cgoCheckPointer_EVP_DigestUpdate(EVP_MD_CTX *ctx, uintptr_t d, size_t cnt) {
    return EVP_DigestUpdate(ctx, (const void *) d, cnt);
}

*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type SHA256Hash struct {
	ctx    C.EVP_MD_CTX
	engine *Engine
}

func NewSHA256Hash() (*SHA256Hash, error) { return NewSHA256HashWithEngine(nil) }

func NewSHA256HashWithEngine(e *Engine) (*SHA256Hash, error) {
	hash := &SHA256Hash{engine: e}
	C.EVP_MD_CTX_init(&hash.ctx)
	runtime.SetFinalizer(hash, func(hash *SHA256Hash) { hash.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}
	return hash, nil
}

func (s *SHA256Hash) Close() {
	C.EVP_MD_CTX_cleanup(&s.ctx)
}

func (s *SHA256Hash) Reset() error {
	if 1 != C.EVP_DigestInit_ex(&s.ctx, C.EVP_sha256(), engineRef(s.engine)) {
		return errors.New("openssl: sha256: cannot init digest ctx")
	}
	return nil
}

func (s *SHA256Hash) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C._avoid_cgoCheckPointer_EVP_DigestUpdate(&s.ctx,
		C.uintptr_t(uintptr(unsafe.Pointer(&p[0]))),
		C.size_t(len(p))) {
		return 0, errors.New("openssl: sha256: cannot update digest")
	}
	return len(p), nil
}

func (s *SHA256Hash) Sum() (result [32]byte, err error) {
	if 1 != C.EVP_DigestFinal_ex(&s.ctx,
		(*C.uchar)(unsafe.Pointer(&result[0])), nil) {
		return result, errors.New("openssl: sha256: cannot finalize ctx")
	}
	return result, s.Reset()
}

func SHA256(data []byte) (result [32]byte, err error) {
	hash, err := NewSHA256Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	return hash.Sum()
}
