// Copyright (C) 2017. See AUTHORS.
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

type CRL struct {
	x   *C.X509_CRL
	ref interface{}
}

// LoadCRLFromPEM loads an X509_CRL from a PEM-encoded block.
func LoadCRLFromPEM(pem_block []byte) (*CRL, error) {
	if len(pem_block) == 0 {
		return nil, errors.New("empty pem block")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem_block[0]),
		C.int(len(pem_block)))
	crl := C.PEM_read_bio_X509_CRL(bio, nil, nil, nil)
	C.BIO_free(bio)
	if crl == nil {
		return nil, errorFromErrorQueue()
	}
	x := &CRL{x: crl}
	runtime.SetFinalizer(x, func(x *CRL) {
		C.X509_CRL_free(x.x)
	})
	return x, nil
}

func (c *CRL) GetIssuer() (*Name, error) {
	n := C.X509_CRL_get_issuer(c.x)
	if n == nil {
		return nil, errors.New("failed to get issuer")
	}
	return &Name{name: n}, nil
}
