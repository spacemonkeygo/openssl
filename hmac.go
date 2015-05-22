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
#include "openssl/hmac.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

type HMAC struct {
	ctx    C.HMAC_CTX
	engine *Engine
	md     *C.EVP_MD
}

func NewHMAC(key []byte, digestAlgorithm EVP_MD) (*HMAC, error) {
	return NewHMACWithEngine(key, digestAlgorithm, nil)
}

func NewHMACWithEngine(key []byte, digestAlgorithm EVP_MD, e *Engine) (*HMAC, error) {
	var md *C.EVP_MD = getDigestFunction(digestAlgorithm)
	hmac := &HMAC{engine: e, md: md}
	C.HMAC_CTX_init(&hmac.ctx)
	C.HMAC_Init_ex(&hmac.ctx,
		unsafe.Pointer(&key[0]),
		C.int(len(key)),
		md,
		nil)

	runtime.SetFinalizer(hmac, func(hmac *HMAC) { hmac.Close() })
	return hmac, nil
}

func (h *HMAC) Close() {
	C.HMAC_CTX_cleanup(&h.ctx)
}

func (s *HMAC) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return 0, nil
	}
	C.HMAC_Update(&s.ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	return len(data), nil
}

func (h *HMAC) Reset() error {
	C.HMAC_Init_ex(&h.ctx, nil, 0, nil, nil)
	return nil
}

func (h *HMAC) Final() (result []byte, err error) {
	mdLength := C.EVP_MD_size(h.md)
	result = make([]byte, mdLength)
	C.HMAC_Final(&h.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), (*C.uint)(unsafe.Pointer(&mdLength)))
	return result, h.Reset()
}
