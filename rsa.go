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
	"fmt"
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

// VerifyRSASignature verifies that a signature is valid for some data and a Public Key
// - Parameter publicKey: The OpenSSL EVP_PKEY public key in DER format
// - Parameter signature: The signature to verify in DER format
// - Parameter data: The data used to generate the signature
// - Parameter digestType: The type of the digest to use. The currently supported values are: sha1, sha224, sha256, sha384, sha512, ripemd160
// - Parameter pkeyopt: A map of any algorithm specific control operations in string form
// - Returns: True if the signature was verified
func VerifyRSASignature(publicKey, signature, data []byte, digestType string, pkeyopt map[string]string) (bool, error) {
	
	md, err := GetDigestByName(digestType)
	if err != nil {
		return false, err
	}

	inf := C.BIO_new(C.BIO_s_mem())
	if inf == nil {
		return false, errors.New("failed allocating input buffer")
	}
	defer C.BIO_free(inf)
	_, err = asAnyBio(inf).Write(publicKey)
	if err != nil {
		return false, err
	}
	pubKey := C.d2i_PUBKEY_bio(inf, nil)
	if pubKey == nil {
		return false, errors.New("failed to load public key")
	}
	defer C.EVP_PKEY_free(pubKey)
	ctx := C.EVP_PKEY_CTX_new(pubKey, nil)
	if ctx == nil {
		return false, errors.New("failed to setup context")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	mdctx := C.EVP_MD_CTX_new()
	defer C.EVP_MD_CTX_free(mdctx)

	nRes := C.EVP_DigestVerifyInit(mdctx, &ctx, md.ptr, nil, pubKey)
	if nRes != 1 {
		return false, errors.New("unable to init digest verify")
	}

	if pkeyopt != nil && len(pkeyopt) > 0 {
		for k, v := range pkeyopt {
			if C.X_EVP_PKEY_CTX_ctrl_str(ctx, C.CString(k), C.CString(v)) <= 0 {
				return false, fmt.Errorf("failed to set %s", k)
			}
		}
	}

	nRes = C.EVP_DigestUpdate(mdctx, unsafe.Pointer((*C.uchar)(&data[0])), C.size_t(len(data)))
	if nRes != 1 {
		return false, errors.New("unable to update digest")
	}

	nRes = C.EVP_DigestVerifyFinal(mdctx, (*C.uchar)(&signature[0]), C.size_t(len(signature)))
	if nRes != 1 {
		return false, nil
	}

	return true, nil
}