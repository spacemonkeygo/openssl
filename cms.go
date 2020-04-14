package openssl

// #include "shim.h"
import "C"

import (
	"errors"
	"unsafe"
)

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
