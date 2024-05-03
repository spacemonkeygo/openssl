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

// VerifyAndGetSignedDataFromPKCS7 verifies a CMS SignedData structure from a DER-encoded PKCS7,
// and returns the signed content if the verification is successful.
// It does not verify the signing certificates.
func VerifyAndGetSignedDataFromPKCS7(der []byte) ([]byte, error) {
	if len(der) == 0 {
		return nil, errors.New("empty der block")
	}

	in := C.BIO_new_mem_buf(unsafe.Pointer(&der[0]), C.int(len(der)))
	if in == nil {
		return nil, errors.New("failed creating input buffer")
	}
	defer C.BIO_free(in)

	var cms *C.CMS_ContentInfo
	cms = C.d2i_CMS_bio(in, nil)
	if cms == nil {
		return nil, errors.New("failed creating cms")
	}
	defer C.CMS_ContentInfo_free(cms)

	out := C.BIO_new(C.BIO_s_mem())
	if out == nil {
		return nil, errors.New("failed allocating output buffer")
	}
	defer C.BIO_free(out)
	flags := C.uint(C.CMS_NO_SIGNER_CERT_VERIFY)

	if int(C.CMS_verify(cms, nil, nil, nil, out, flags)) != 1 {
		return nil, errors.New("failed to verify signature")
	}

	bufLen := C.BIO_ctrl(out, C.BIO_CTRL_PENDING, 0, nil)
	buffer := C.X_OPENSSL_malloc(C.ulong(bufLen))
	if buffer == nil {
		return nil, errors.New("failed allocating buffer for signed data")
	}
	defer C.X_OPENSSL_free(buffer)
	C.BIO_read(out, buffer, C.int(bufLen))
	sigData := C.GoBytes(unsafe.Pointer(buffer), C.int(bufLen))

	return sigData, nil
}
