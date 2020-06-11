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
	"unsafe"
)

// VerifyRecoverRSASignature takes a DER encoded RSA public key and a raw signature
// (assuming no padding currently) and returns the recoverable part of the signed data.
// This follows the example shown here: https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_verify_recover.html
// This should be roughly equivalent to the following openssl CLI command:
// openssl rsautl -verify -pubin -inkey publicKey.pem -in signature.bin -raw
func VerifyRecoverRSASignature(publicKey, signature []byte) ([]byte, error) {
	// Read RSA Public Key
	inf := C.BIO_new(C.BIO_s_mem())
	if inf == nil {
		return nil, errors.New("failed allocating input buffer")
	}
	defer C.BIO_free(inf)
	_, err := asAnyBio(inf).Write(publicKey)
	if err != nil {
		return nil, err
	}
	pubKey := C.d2i_PUBKEY_bio(inf, nil)
	if pubKey == nil {
		return nil, errors.New("failed to load public key")
	}
	defer C.EVP_PKEY_free(pubKey)

	// Setup context
	ctx := C.EVP_PKEY_CTX_new(pubKey, nil)
	if ctx == nil {
		return nil, errors.New("failed to setup context")
	}
	defer C.EVP_PKEY_CTX_free(ctx)
	if C.EVP_PKEY_verify_recover_init(ctx) <= 0 {
		return nil, errors.New("failed to initialize verify recover")
	}
	if C.X_EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_NO_PADDING) <= 0 {
		return nil, errors.New("failed to set rsa padding")
	}

	// Determine buffer length
	var routlen C.size_t
	routlen = C.size_t(len(signature))
	if C.EVP_PKEY_verify_recover(ctx, nil, &routlen, (*C.uchar)(&signature[0]), C.size_t(len(signature))) <= 0 {
		return nil, errors.New("error getting buffer length")
	}

	// Recover the signed data
	rout := C.X_OPENSSL_malloc(routlen)
	if rout == nil {
		return nil, errors.New("failed allocating rout")
	}
	defer C.X_OPENSSL_free(rout)
	if C.EVP_PKEY_verify_recover(ctx, (*C.uchar)(rout), &routlen, (*C.uchar)(&signature[0]), C.size_t(len(signature))) <= 0 {
		return nil, errors.New("error recovering signed data")
	}
	recoveredBytes := C.GoBytes(unsafe.Pointer(rout), C.int(routlen))
	return recoveredBytes, nil
}
