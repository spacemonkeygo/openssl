package openssl

// #include "shim.h"
import "C"

import (
	"errors"
	"io/ioutil"
)

// ASN1Parse parses and extracts ASN.1 structure and returns the data in text format
func ASN1Parse(asn1 []byte) (string, error) {
	if len(asn1) == 0 {
		return "", errors.New("empty asn1 structure")
	}

	out := C.BIO_new(C.BIO_s_mem())
	if out == nil {
		return "", errors.New("failed allocating output buffer")
	}
	defer C.BIO_free(out)

	if int(C.ASN1_parse_dump(out, (*C.uchar)(&asn1[0]), C.long(len(asn1)), 1, 0)) == 0 {
		return "", errors.New("failed to parse asn1 data")
	}

	parsed, err := ioutil.ReadAll(asAnyBio(out))
	if err != nil {
		return "", errors.New("failed to read bio data as bytes")
	}

	return string(parsed), nil
}
