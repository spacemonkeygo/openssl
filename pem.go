// Copyright (C) 2014 Space Monkey, Inc.
// +build cgo

package openssl

// #include <openssl/ssl.h>
// #include <openssl/conf.h>
import "C"

import (
	"errors"
	"io/ioutil"
	"runtime"
	"unsafe"
)

type PublicKey interface {
	// MarshalPKIXPublicKeyPEM converts the public key to PEM-encoded PKIX
	// format
	MarshalPKIXPublicKeyPEM() (pem_block []byte, err error)

	// MarshalPKIXPublicKeyDER converts the public key to DER-encoded PKIX
	// format
	MarshalPKIXPublicKeyDER() (der_block []byte, err error)

	evpPKey() *C.EVP_PKEY
}

type PrivateKey interface {
	PublicKey

	// MarshalPKCS1PrivateKeyPEM converts the private key to PEM-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyPEM() (pem_block []byte, err error)

	// MarshalPKCS1PrivateKeyDER converts the private key to DER-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyDER() (der_block []byte, err error)
}

type pKey struct {
	key *C.EVP_PKEY
}

func (key *pKey) evpPKey() *C.EVP_PKEY { return key.key }

func (key *pKey) MarshalPKCS1PrivateKeyPEM() (pem_block []byte,
	err error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)
	rsa := (*C.RSA)(C.EVP_PKEY_get1_RSA(key.key))
	if rsa == nil {
		return nil, errors.New("failed getting rsa key")
	}
	defer C.RSA_free(rsa)
	if int(C.PEM_write_bio_RSAPrivateKey(bio, rsa, nil, nil, C.int(0), nil,
		nil)) != 1 {
		return nil, errors.New("failed dumping private key")
	}
	return ioutil.ReadAll(asAnyBio(bio))
}

func (key *pKey) MarshalPKCS1PrivateKeyDER() (der_block []byte,
	err error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)
	rsa := (*C.RSA)(C.EVP_PKEY_get1_RSA(key.key))
	if rsa == nil {
		return nil, errors.New("failed getting rsa key")
	}
	defer C.RSA_free(rsa)
	if int(C.i2d_RSAPrivateKey_bio(bio, rsa)) != 1 {
		return nil, errors.New("failed dumping private key der")
	}
	return ioutil.ReadAll(asAnyBio(bio))
}

func (key *pKey) MarshalPKIXPublicKeyPEM() (pem_block []byte,
	err error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)
	rsa := (*C.RSA)(C.EVP_PKEY_get1_RSA(key.key))
	if rsa == nil {
		return nil, errors.New("failed getting rsa key")
	}
	defer C.RSA_free(rsa)
	if int(C.PEM_write_bio_RSA_PUBKEY(bio, rsa)) != 1 {
		return nil, errors.New("failed dumping public key pem")
	}
	return ioutil.ReadAll(asAnyBio(bio))
}

func (key *pKey) MarshalPKIXPublicKeyDER() (der_block []byte,
	err error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)
	rsa := (*C.RSA)(C.EVP_PKEY_get1_RSA(key.key))
	if rsa == nil {
		return nil, errors.New("failed getting rsa key")
	}
	defer C.RSA_free(rsa)
	if int(C.i2d_RSA_PUBKEY_bio(bio, rsa)) != 1 {
		return nil, errors.New("failed dumping public key der")
	}
	return ioutil.ReadAll(asAnyBio(bio))
}

// LoadPrivateKey loads a private key from a PEM-encoded block.
func LoadPrivateKey(pem_block []byte) (PrivateKey, error) {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem_block[0]),
		C.int(len(pem_block)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	rsakey := C.PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil)
	if rsakey == nil {
		return nil, errors.New("failed reading rsa key")
	}
	defer C.RSA_free(rsakey)

	// convert to PKEY
	key := C.EVP_PKEY_new()
	if key == nil {
		return nil, errors.New("failed converting to evp_pkey")
	}
	if C.EVP_PKEY_set1_RSA(key, (*C.struct_rsa_st)(rsakey)) != 1 {
		C.EVP_PKEY_free(key)
		return nil, errors.New("failed converting to evp_pkey")
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.EVP_PKEY_free(p.key)
	})
	return p, nil
}

type Certificate struct {
	x *C.X509
}

// LoadCertificate loads an X509 certificate from a PEM-encoded block.
func LoadCertificate(pem_block []byte) (*Certificate, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem_block[0]),
		C.int(len(pem_block)))
	cert := C.PEM_read_bio_X509(bio, nil, nil, nil)
	C.BIO_free(bio)
	if cert == nil {
		return nil, errorFromErrorQueue()
	}
	x := &Certificate{x: cert}
	runtime.SetFinalizer(x, func(x *Certificate) {
		C.X509_free(x.x)
	})
	return x, nil
}

// MarshalPEM converts the X509 certificate to PEM-encoded format
func (c *Certificate) MarshalPEM() (pem_block []byte, err error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)
	if int(C.PEM_write_bio_X509(bio, c.x)) != 1 {
		return nil, errors.New("failed dumping certificate")
	}
	return ioutil.ReadAll(asAnyBio(bio))
}

// PublicKey returns the public key embedded in the X509 certificate.
func (c *Certificate) PublicKey() (PublicKey, error) {
	pkey := C.X509_get_pubkey(c.x)
	if pkey == nil {
		return nil, errors.New("no public key found")
	}
	key := &pKey{key: pkey}
	runtime.SetFinalizer(key, func(key *pKey) {
		C.EVP_PKEY_free(key.key)
	})
	return key, nil
}
