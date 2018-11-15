// Copyright (C) 2015 Space Monkey, Inc.
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

// #include <openssl/bio.h>
// #include <openssl/ssl.h>
// #include <openssl/evp.h>
// #include <openssl/x509.h>
// #include <openssl/pkcs12.h>
// #include <openssl/safestack.h>
//
// typedef STACK_OF(X509) OPENSSL_STACK_OF_X509;
//
// OPENSSL_STACK_OF_X509* sk_X509_new_null_wrap() {
// 	return sk_X509_new_null();
// }
//
// int sk_X509_push_wrap(OPENSSL_STACK_OF_X509 *sk, X509 *x509) {
// 	return sk_X509_push(sk, x509);
// }
//
// void sk_X509_free_wrap(OPENSSL_STACK_OF_X509 *sk) {
// 	return sk_X509_free(sk);
// }
//
// int sk_X509_num_wrap(OPENSSL_STACK_OF_X509 *sk) {
// 	return sk_X509_num(sk);
// }
//
// X509 *sk_X509_value_wrap(OPENSSL_STACK_OF_X509 *sk, int i) {
// 	return sk_X509_value(sk, i);
// }
// int BIO_flush_wrap(BIO *b) {
// 	return BIO_flush(b);
// }
//
import "C"

import (
	"errors"
	"io/ioutil"
	"runtime"
	"unsafe"
)

type PKCS12 struct {
	Name        string
	Certificate *Certificate
	PrivateKey  PrivateKey
	CaCerts     []*Certificate
}

// Marshal the pkcs12 data with default options
func (this *PKCS12) Marshal(password string) ([]byte, error) {
	return this.MarshalEx(password, 2048, 1, 0)
}

// Marshal the pkcs12 data
func (this *PKCS12) MarshalEx(password string, iter int, maciter int, keyType int) ([]byte, error) {
	var cPKey *C.EVP_PKEY
	var cCACerts *C.OPENSSL_STACK_OF_X509
	// Get the certificate
	if this.Certificate == nil {
		return nil, errors.New("Require certificate")
	}
	// Get the private key
	switch this.PrivateKey.(type) {
	case *pKey:
		// The pointer of pKey struct
		cPKey = this.PrivateKey.(*pKey).key
	default:
		return nil, errors.New("Unsupported private key type")
	}
	// Get the ca certificates
	if len(this.CaCerts) > 0 {
		cCACerts = C.sk_X509_new_null_wrap()
		if cCACerts == nil {
			return nil, errors.New("Failed to create STACK_OF(X509)")
		}
		defer C.sk_X509_free_wrap(cCACerts)
		for _, caCert := range this.CaCerts {
			if C.sk_X509_push_wrap(cCACerts, caCert.x) <= 0 {
				return nil, errors.New("Failed to add ca certificate")
			}
		}
	}
	// Create the pkcs12
	var pass *C.char = nil
	if len(password) > 0 {
		pass = C.CString(password)
		defer C.free(unsafe.Pointer(pass))
	}
	var name *C.char = nil
	if len(this.Name) > 0 {
		name = C.CString(this.Name)
		defer C.free(unsafe.Pointer(name))
	}
	pkcs12 := C.PKCS12_create(
		pass,
		name,
		cPKey,
		this.Certificate.x,
		cCACerts,
		C.int(NID_pbe_WithSHA1And3_Key_TripleDES_CBC),
		C.int(NID_pbe_WithSHA1And3_Key_TripleDES_CBC),
		C.int(iter),
		C.int(maciter),
		C.int(keyType),
	)
	if pkcs12 == nil {
		return nil, errors.New("Failed to create PKCS12 object")
	}
	defer C.PKCS12_free(pkcs12)
	// Export
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("Failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)
	bytesCount := C.i2d_PKCS12_bio(bio, pkcs12)
	if bytesCount <= 0 {
		return nil, errors.New("Failed to dump PKCS12 object")
	}
	C.BIO_flush_wrap(bio)
	return ioutil.ReadAll(asAnyBio(bio))
}

func UnmarshalPKCS12(bytes []byte, password string) (*PKCS12, error) {
	if len(bytes) == 0 {
		return nil, errors.New("Empty pkcs12 bytes")
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&bytes[0]), C.int(len(bytes)))
	if bio == nil {
		return nil, errors.New("Failed to create memory BIO")
	}
	defer C.BIO_free(bio)
	pkcs12 := C.d2i_PKCS12_bio(bio, nil)
	if pkcs12 == nil {
		return nil, errorFromErrorQueue()
	}
	defer C.PKCS12_free(pkcs12)
	// Parse the pkcs12
	var pass *C.char = nil
	if len(password) > 0 {
		pass = C.CString(password)
		defer C.free(unsafe.Pointer(pass))
	}
	var cX509 *C.X509
	var cPKey *C.EVP_PKEY
	var cCACerts *C.OPENSSL_STACK_OF_X509
	if C.PKCS12_parse(pkcs12, pass, &cPKey, &cX509, &cCACerts) != 1 {
		return nil, errorFromErrorQueue()
	}
	if cCACerts != nil {
		defer C.sk_X509_free_wrap(cCACerts)
	}
	if cX509 == nil {
		return nil, errors.New("No certificate found")
	}
	if cPKey == nil {
		return nil, errors.New("No private key found")
	}
	// Load certificate and name alias
	cert := &Certificate{x: cX509}
	// Set finalizer
	runtime.SetFinalizer(cert, func(x *Certificate) {
		C.X509_free(cert.x)
	})
	var name string
	var cNameLength C.int
	cName := C.X509_alias_get0(cX509, &cNameLength)
	if cName != nil {
		defer C.free(unsafe.Pointer(cName))
		name = string(C.GoBytes(unsafe.Pointer(cName), cNameLength))
	}
	// Load private key
	key := &pKey{key: cPKey}
	runtime.SetFinalizer(key, func(p *pKey) {
		C.EVP_PKEY_free(p.key)
	})
	// Load ca certificates
	var caCerts []*Certificate
	if cCACerts != nil {
		caCertCount := int(C.sk_X509_num_wrap(cCACerts))
		if caCertCount > 0 {
			caCerts = make([]*Certificate, caCertCount)
			for i := 0; i < caCertCount; i++ {
				cCACert := C.sk_X509_value_wrap(cCACerts, C.int(i))
				caCert := &Certificate{x: cCACert}
				// Set finalizer
				runtime.SetFinalizer(caCert, func(x *Certificate) {
					C.X509_free(caCert.x)
				})
				caCerts[i] = caCert
			}
		}
	}
	// Done
	return &PKCS12{Name: name, Certificate: cert, PrivateKey: key, CaCerts: caCerts}, nil
}
