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

package openssl

// #include "shim.h"
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type SHA384Hash struct {
	ctx    *C.EVP_MD_CTX
	engine *Engine
}

func NewSHA384Hash() (*SHA384Hash, error) { return NewSHA384HashWithEngine(nil) }

func NewSHA384HashWithEngine(e *Engine) (*SHA384Hash, error) {
	hash := &SHA384Hash{engine: e}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, errors.New("openssl: sha256: unable to allocate ctx")
	}
	runtime.SetFinalizer(hash, func(hash *SHA384Hash) { hash.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}
	return hash, nil
}

func (s *SHA384Hash) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *SHA384Hash) Reset() error {
	if 1 != C.X_EVP_DigestInit_ex(s.ctx, C.EVP_sha384(), engineRef(s.engine)) {
		return errors.New("openssl: sha384: cannot init digest ctx")
	}
	return nil
}

func (s *SHA384Hash) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&p[0]),
		C.size_t(len(p))) {
		return 0, errors.New("openssl: sha384: cannot update digest")
	}
	return len(p), nil
}

func (s *SHA384Hash) Sum() (result [48]byte, err error) {
	if 1 != C.X_EVP_DigestFinal_ex(s.ctx,
		(*C.uchar)(unsafe.Pointer(&result[0])), nil) {
		return result, errors.New("openssl: sha384: cannot finalize ctx")
	}
	return result, s.Reset()
}

func SHA384(data []byte) (result [48]byte, err error) {
	hash, err := NewSHA384Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	return hash.Sum()
}
