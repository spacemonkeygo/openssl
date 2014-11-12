// Copyright (C) 2014 Space Monkey, Inc.
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

// #include <openssl/conf.h>
// #include <openssl/ssl.h>
// #include <openssl/x509v3.h>
//
// void OPENSSL_free_not_a_macro(void *ref) { OPENSSL_free(ref); }
//
import "C"

import (
	"errors"
	"fmt"
	"io/ioutil"
	"runtime"
	"time"
	"unsafe"
)

const (
	MBSTRING_ASC = 0x1001
)

type Certificate struct {
	x      *C.X509
	Issuer *Certificate
	ref    interface{}
}

type CertificateInfo struct {
	Serial       int
	Issued       time.Duration
	Expires      time.Duration
	Country      string
	Organization string
	CommonName   string
}

type Name struct {
	name *C.X509_NAME
}

// Allocate and return a new Name object.
func NewName() (*Name, error) {
	n := C.X509_NAME_new()
	if n == nil {
		return nil, errors.New("could not create x509 name")
	}
	return &Name{name: n}, nil
}

// GC sets the underlying X509_NAME object to be freed
// when the Go object is released.
func (n *Name) GC() {
	runtime.SetFinalizer(n, func(n *Name) {
		C.X509_NAME_free(n.name)
	})
}

// AddTextEntry populates
func (n *Name) AddTextEntry(field, value string) error {
	cfield := C.CString(field)
	cvalue := (*C.uchar)(unsafe.Pointer(&[]byte(value)[0]))
	ret := C.X509_NAME_add_entry_by_txt(
		n.name, cfield, MBSTRING_ASC, cvalue, -1, -1, 0)
	if ret == 0 {
		return errors.New("failed to add x509 name text entry")
	}
	return nil
}

// AddTextEntries allows adding multiple entries to a name in one call.
func (n *Name) AddTextEntries(entries map[string]string) error {
	for f, v := range entries {
		if err := n.AddTextEntry(f, v); err != nil {
			return err
		}
	}
	return nil
}

// NewCertificate generates a basic certificate based
// on the provided CertificateInfo struct
func NewCertificate(info *CertificateInfo, key PublicKey) (*Certificate, error) {
	c := &Certificate{x: C.X509_new()}
	runtime.SetFinalizer(c, func(c *Certificate) {
		C.X509_free(c.x)
	})

	name, err := c.GetSubjectName()
	if err != nil {
		return nil, err
	}
	err = name.AddTextEntries(map[string]string{
		"C":  info.Country,
		"O":  info.Organization,
		"CN": info.CommonName,
	})
	if err != nil {
		return nil, err
	}
	if err := c.SetSerial(info.Serial); err != nil {
		return nil, err
	}
	if err := c.SetIssueDate(info.Issued); err != nil {
		return nil, err
	}
	if err := c.SetExpireDate(info.Expires); err != nil {
		return nil, err
	}
	if err := c.SetPubKey(key); err != nil {
		return nil, err
	}
	// self-issue for now
	if err := c.SetIssuerName(name); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Certificate) GetSubjectName() (*Name, error) {
	n := C.X509_get_subject_name(c.x)
	if n == nil {
		return nil, errors.New("failed to get subject name")
	}
	return &Name{name: n}, nil
}

func (c *Certificate) GetIssuerName() (*Name, error) {
	n := C.X509_get_issuer_name(c.x)
	if n == nil {
		return nil, errors.New("failed to get issuer name")
	}
	return &Name{name: n}, nil
}

func (c *Certificate) SetSubjectName(name *Name) error {
	// TODO: garbage collection of old name?
	if C.X509_set_subject_name(c.x, name.name) == 0 {
		return errors.New("failed to set subject name")
	}
	return nil
}

// SetIssuer updates the stored Issuer cert
// and the internal x509 Issuer Name of a certificate.
// The stored Issuer reference is used when adding extensions.
func (c *Certificate) SetIssuer(issuer *Certificate) error {
	name, err := issuer.GetSubjectName()
	if err != nil {
		return err
	}
	if err = c.SetIssuerName(name); err != nil {
		return err
	}
	c.Issuer = issuer
	return nil
}

// SetIssuerName populates the issuer name of a certificate.
// Use SetIssuer instead.
func (c *Certificate) SetIssuerName(name *Name) error {
	// TODO: garbage collection of old name?
	if C.X509_set_issuer_name(c.x, name.name) == 0 {
		return errors.New("failed to set subject name")
	}
	return nil
}

// SetSerial sets the serial of a certificate.
func (c *Certificate) SetSerial(serial int) error {
	if C.ASN1_INTEGER_set(C.X509_get_serialNumber(c.x), C.long(serial)) == 0 {
		return errors.New("failed to set serial")
	}
	return nil
}

// SetIssueDate sets the certificate issue date relative to the current time.
func (c *Certificate) SetIssueDate(when time.Duration) error {
	offset := C.long(when / time.Second)
	result := C.X509_gmtime_adj(c.x.cert_info.validity.notBefore, offset)
	if result == nil {
		return errors.New("failed to set issue date")
	}
	return nil
}

// SetExpireDate sets the certificate issue date relative to the current time.
func (c *Certificate) SetExpireDate(when time.Duration) error {
	offset := C.long(when / time.Second)
	result := C.X509_gmtime_adj(c.x.cert_info.validity.notAfter, offset)
	if result == nil {
		return errors.New("failed to set expire date")
	}
	return nil
}

// SetPubKey assigns a new public key to a certificate.
func (c *Certificate) SetPubKey(pubKey PublicKey) error {
	if C.X509_set_pubkey(c.x, pubKey.evpPKey()) == 0 {
		return errors.New("failed to set public key")
	}
	return nil
}

// Sign a certificate using a private key and a digest name.
// Accepted digest names are 'sha256', 'sha384', and 'sha512'.
func (c *Certificate) Sign(privKey PrivateKey, digest string) error {
	switch digest {
	case "sha256":
	case "sha384":
	case "sha512":
	default:
		return fmt.Errorf("Unsupported digest '%s'."+
			"You're probably looking for 'sha256' or 'sha512'.", digest)
	}
	return c.insecureSign(privKey, digest)
}

func (c *Certificate) insecureSign(privKey PrivateKey, digest string) error {
	var md *C.EVP_MD
	switch digest {
	// please don't use these digest functions
	case "null":
		md = C.EVP_md_null()
	case "md5":
		md = C.EVP_md5()
	case "sha":
		md = C.EVP_sha()
	case "sha1":
		md = C.EVP_sha1()
	case "dss":
		md = C.EVP_dss()
	case "dss1":
		md = C.EVP_dss1()
	case "mdc2":
		md = C.EVP_mdc2()
	case "ripemd160":
		md = C.EVP_ripemd160()
	case "sha224":
		md = C.EVP_sha224()
	// you actually want one of these
	case "sha256":
		md = C.EVP_sha256()
	case "sha384":
		md = C.EVP_sha384()
	case "sha512":
		md = C.EVP_sha512()
	default:
		return fmt.Errorf("Unsupported hash function '%s'.")
	}
	if C.X509_sign(c.x, privKey.evpPKey(), md) == 0 {
		return errors.New("failed to sign certificate")
	}
	return nil
}

// Add an extension to a certificate.
// Extension constants are NID_* as found in openssl.
func (c *Certificate) AddExtension(nid int, value string) error {
	issuer := c
	if c.Issuer != nil {
		issuer = c.Issuer
	}
	var ctx C.X509V3_CTX
	C.X509V3_set_ctx(&ctx, c.x, issuer.x, nil, nil, 0)
	ex := C.X509V3_EXT_conf_nid(nil, &ctx, C.int(nid), C.CString(value))
	if ex == nil {
		return errors.New("failed to create x509v3 extension")
	}
	if C.X509_add_ext(c.x, ex, -1) == 0 {
		return errors.New("failed to add x509v3 extension")
	}
	C.X509_EXTENSION_free(ex)
	return nil
}

func (c *Certificate) AddExtensions(extensions map[int]string) error {
	for nid, value := range extensions {
		if err := c.AddExtension(nid, value); err != nil {
			return err
		}
	}
	return nil
}

// LoadCertificateFromPEM loads an X509 certificate from a PEM-encoded block.
func LoadCertificateFromPEM(pem_block []byte) (*Certificate, error) {
	if len(pem_block) == 0 {
		return nil, errors.New("empty pem block")
	}
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

// GetSerialNumberHex returns the certificate's serial number in hex format
func (c *Certificate) GetSerialNumberHex() (serial string) {
	asn1_i := C.X509_get_serialNumber(c.x)
	bignum := C.ASN1_INTEGER_to_BN(asn1_i, nil)
	hex := C.BN_bn2hex(bignum)
	serial = C.GoString(hex)
	C.BN_free(bignum)
	C.OPENSSL_free_not_a_macro(unsafe.Pointer(hex))
	return
}
