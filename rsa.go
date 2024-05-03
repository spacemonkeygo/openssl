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
	"math/big"
	"strconv"
	"unsafe"
)

var pkeyoptSkip = []string{
	"rsa_padding_mode",
	"rsa_pss_saltlen",
}

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
		// This is a convenience function for calling X_EVP_PKEY_CTX_ctrl_str. The _Ctype_struct_evp_pkey_ctx_st type is not
		// exposed, but ctx can be captured in a local function like this.
		setKeyOpt := func(pkeyopt map[string]string, k string) error {
			v, ok := pkeyopt[k]
			if !ok {
				return nil
			}
			ck := C.CString(k)
			defer C.free(unsafe.Pointer(ck))
			cv := C.CString(v)
			defer C.free(unsafe.Pointer(cv))
			if C.X_EVP_PKEY_CTX_ctrl_str(ctx, ck, cv) <= 0 {
				return fmt.Errorf("failed to set %s", k)
			}
			return nil
		}

		// Set RSA padding mode and salt length if they exist. Order matters; mode must be set before salt length.
		if rsaPaddingMode, ok := pkeyopt["rsa_padding_mode"]; ok {
			if err := setKeyOpt(pkeyopt, "rsa_padding_mode"); err != nil {
				return false, err
			}
			switch rsaPaddingMode {
			case "pss":
				if err := setKeyOpt(pkeyopt, "rsa_pss_saltlen"); err != nil {
					return false, err
				}
			}
		}

		// Fallback to make sure all pkeyopt get processed. Skips any keys found in pkeyoptSkip.
		for k := range pkeyopt {
			if contains(pkeyoptSkip, k) {
				continue
			}
			if err := setKeyOpt(pkeyopt, k); err != nil {
				return false, err
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

func contains(items []string, s string) bool {
	for _, v := range items {
		if v == s {
			return true
		}
	}
	return false
}

// RSAPublicKey represents the public part of an RSA key.
type RSAPublicKey struct {
	N *big.Int // modulus
	E int      // public exponent
}

// This function specifically expects an RSA public key DER encoded in the PKCS#1 format
func ParseRSAPublicKeyPKCS1(publicKey []byte) (key *RSAPublicKey, err error) {
	inf := C.BIO_new(C.BIO_s_mem())
	if inf == nil {
		return nil, errors.New("failed allocating input buffer")
	}
	defer C.BIO_free(inf)
	_, err = asAnyBio(inf).Write(publicKey)
	if err != nil {
		return nil, err
	}

	rsa := C.d2i_RSA_PUBKEY_bio(inf, nil)
	if rsa == nil {
		return nil, errors.New("failed to load public key")
	}
	defer C.RSA_free(rsa)

	var n, e *C.BIGNUM
	C.RSA_get0_key(rsa, &n, &e, nil)
	// Note: purposely not calling BN_free on n & e, because they are cleaned up by RSA_free.
	// Calling both results in an intermittent SIGTERM.

	CmodulusHex := C.BN_bn2hex(n)
	defer C.X_OPENSSL_free(unsafe.Pointer(CmodulusHex))
	CexponentHex := C.BN_bn2hex(e)
	defer C.X_OPENSSL_free(unsafe.Pointer(CexponentHex))

	modulusHex := C.GoString(CmodulusHex)
	exponentHex := C.GoString(CexponentHex)

	ret := &RSAPublicKey{N: new(big.Int)}
	ret.N.SetString(modulusHex, 16)
	exponent, err := strconv.ParseInt(exponentHex, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to convert hex exponent to int: %v", err)
	}
	ret.E = int(exponent)

	return ret, nil
}
