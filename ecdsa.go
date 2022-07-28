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

// VerifyECDSASignature verifies data valid against an ECDSA signature and ECDSA Public Key
// - Parameter publicKey: The OpenSSL EVP_PKEY ECDSA public key in DER format
// - Parameter signature: The ECDSA signature to verify in DER format
// - Parameter data: The raw data used to generate the signature
// - Parameter digest: The name of the digest to use. The currently supported values are: sha1, sha224, sha256, sha384, sha512
// - Returns: True if the signature was verified
func VerifyECDSASignature(publicKey, signature, data []byte, digest string) (bool, error) {
	// read EC Public Key
	inf := C.BIO_new(C.BIO_s_mem())
	if inf == nil {
		return false, errors.New("failed allocating input buffer")
	}
	defer C.BIO_free(inf)
	_, err := asAnyBio(inf).Write(publicKey)
	if err != nil {
		return false, err
	}

	eckey := C.d2i_EC_PUBKEY_bio(inf, nil)
	if eckey == nil {
		return false, errors.New("failed to load ec public key")
	}
	defer C.EC_KEY_free(eckey)

	out := C.BIO_new(C.BIO_s_mem())
	if out == nil {
		return false, errors.New("failed allocating output buffer")
	}
	defer C.BIO_free(out)
	i := C.PEM_write_bio_EC_PUBKEY(out, eckey)
	if i != 1 {
		return false, errors.New("failed to write bio ec public key")
	}
	pemKey := C.PEM_read_bio_PUBKEY(out, nil, nil, nil)
	defer C.EVP_PKEY_free(pemKey)

	keyType := C.EVP_PKEY_base_id(pemKey)
	if keyType != C.EVP_PKEY_EC {
		return false, errors.New("public key is incorrect type")
	}

	var digestType *C.EVP_MD
	switch digest {
	case "sha1":
		digestType = C.EVP_sha1()
	case "sha224":
		digestType = C.EVP_sha224()
	case "sha256":
		digestType = C.EVP_sha256()
	case "sha384":
		digestType = C.EVP_sha384()
	case "sha512":
		digestType = C.EVP_sha512()
	default:
		return false, errors.New("unsupported digest value")
	}

	// run digest verify with public key in pem format, signature in der format, and data in raw format
	mdctx := C.EVP_MD_CTX_new()
	nRes := C.EVP_DigestVerifyInit(mdctx, nil, digestType, nil, pemKey)
	if nRes != 1 {
		return false, errors.New("unable to init digest verify")
	}
	defer C.EVP_MD_CTX_free(mdctx)
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

// GetECPublicKeyBitSize returns the bit size of an EC public key, using EVP_PKEY_bits.
func GetECPublicKeyBitSize(publicKey []byte) (int, error) {
	inf := C.BIO_new(C.BIO_s_mem())
	if inf == nil {
		return 0, errors.New("failed allocating input buffer")
	}
	defer C.BIO_free(inf)
	_, err := asAnyBio(inf).Write(publicKey)
	if err != nil {
		return 0, err
	}

	eckey := C.d2i_EC_PUBKEY_bio(inf, nil)
	if eckey == nil {
		return 0, errors.New("failed to load ec public key")
	}
	defer C.EC_KEY_free(eckey)

	out := C.BIO_new(C.BIO_s_mem())
	if out == nil {
		return 0, errors.New("failed allocating output buffer")
	}
	defer C.BIO_free(out)
	i := C.PEM_write_bio_EC_PUBKEY(out, eckey)
	if i != 1 {
		return 0, errors.New("failed to write bio ec public key")
	}
	pemKey := C.PEM_read_bio_PUBKEY(out, nil, nil, nil)
	defer C.EVP_PKEY_free(pemKey)

	bitSize := C.EVP_PKEY_bits(pemKey)
	return int(bitSize), nil
}
