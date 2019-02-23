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

#include "openssl/evp.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type SHAHash struct {
	ctx    C.EVP_MD_CTX
	engine *Engine
}

func NewSHAHash() (*SHAHash, error) { return NewSHAHashWithEngine(nil) }

func NewSHAHashWithEngine(e *Engine) (*SHAHash, error) {
	hash := &SHAHash{engine: e}
	C.EVP_MD_CTX_init(&hash.ctx)
	runtime.SetFinalizer(hash, func(hash *SHAHash) { hash.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}
	return hash, nil
}

func (s *SHAHash) Close() {
	C.EVP_MD_CTX_cleanup(&s.ctx)
}

func (s *SHAHash) Reset() error {
	if 1 != C.EVP_DigestInit_ex(&s.ctx, C.EVP_sha(), engineRef(s.engine)) {
		return errors.New("openssl: sha: cannot init digest ctx")
	}
	return nil
}

func (s *SHAHash) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.EVP_DigestUpdate(&s.ctx, unsafe.Pointer(&p[0]),
		C.size_t(len(p))) {
		return 0, errors.New("openssl: sha: cannot update digest")
	}
	return len(p), nil
}

func (s *SHAHash) Sum() (result [20]byte, err error) {
	if 1 != C.EVP_DigestFinal_ex(&s.ctx,
		(*C.uchar)(unsafe.Pointer(&result[0])), nil) {
		return result, errors.New("openssl: sha: cannot finalize ctx")
	}
	return result, s.Reset()
}

func SHA(data []byte) (result [20]byte, err error) {
	hash, err := NewSHAHash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	return hash.Sum()
}
