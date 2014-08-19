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

/*
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/tls1.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

static long SSL_CTX_set_options_not_a_macro(SSL_CTX* ctx, long options) {
   return SSL_CTX_set_options(ctx, options);
}

static long SSL_CTX_set_mode_not_a_macro(SSL_CTX* ctx, long modes) {
   return SSL_CTX_set_mode(ctx, modes);
}

static long SSL_CTX_get_mode_not_a_macro(SSL_CTX* ctx) {
   return SSL_CTX_get_mode(ctx);
}

static long SSL_CTX_set_session_cache_mode_not_a_macro(SSL_CTX* ctx, long modes) {
   return SSL_CTX_set_session_cache_mode(ctx, modes);
}

static int CRYPTO_add_not_a_macro(int *pointer,int amount,int type) {
   return CRYPTO_add(pointer, amount, type);
}

static long SSL_CTX_add_extra_chain_cert_not_a_macro(SSL_CTX* ctx, X509 *cert) {
    return SSL_CTX_add_extra_chain_cert(ctx, cert);
}

static long SSL_CTX_set_tmp_ecdh_not_a_macro(SSL_CTX* ctx, EC_KEY *key) {
    return SSL_CTX_set_tmp_ecdh(ctx, key);
}

static long SSL_CTX_set_tlsext_ticket_key_cb_not_a_macro(SSL_CTX *sslctx, int (*cb)(SSL *con, unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)) {
    return SSL_CTX_set_tlsext_ticket_key_cb(sslctx, cb);
}

#ifndef SSL_MODE_RELEASE_BUFFERS
#define SSL_MODE_RELEASE_BUFFERS 0
#endif

#ifndef SSL_OP_NO_COMPRESSION
#define SSL_OP_NO_COMPRESSION 0
#endif

static const SSL_METHOD *OUR_TLSv1_1_method() {
#ifdef TLS1_1_VERSION
    return TLSv1_1_method();
#else
    return NULL;
#endif
}

static const SSL_METHOD *OUR_TLSv1_2_method() {
#ifdef TLS1_2_VERSION
    return TLSv1_2_method();
#else
    return NULL;
#endif
}

#ifdef OPENSSL_NO_SHA256
#define tls_session_ticket_md  EVP_sha1
#else
#define tls_session_ticket_md  EVP_sha256
#endif

extern int verify_cb(int ok, X509_STORE_CTX* store);
extern int ticket_cb(SSL *con, unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc);
*/
import "C"

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"unsafe"
	"bytes"

	"github.com/spacemonkeygo/spacelog"
)

var (
	ssl_ctx_idx = C.SSL_CTX_get_ex_new_index(0, nil, nil, nil, nil)

	logger = spacelog.GetLogger()
)

type Ctx struct {
	ctx       *C.SSL_CTX
	verify_cb VerifyCallback
	tickets   []*TLSTicket 
	ticket_cb TLSTicketCallback
}

//export get_ssl_ctx_idx
func get_ssl_ctx_idx() C.int {
	return ssl_ctx_idx
}

func newCtx(method *C.SSL_METHOD) (*Ctx, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx := C.SSL_CTX_new(method)
	if ctx == nil {
		return nil, errorFromErrorQueue()
	}
	c := &Ctx{ctx: ctx}
	C.SSL_CTX_set_ex_data(ctx, get_ssl_ctx_idx(), unsafe.Pointer(c))
	runtime.SetFinalizer(c, func(c *Ctx) {
		C.SSL_CTX_free(c.ctx)
	})
	return c, nil
}

type SSLVersion int

const (
	SSLv3      SSLVersion = 0x02
	TLSv1      SSLVersion = 0x03
	TLSv1_1    SSLVersion = 0x04
	TLSv1_2    SSLVersion = 0x05
	AnyVersion SSLVersion = 0x06
)

// NewCtxWithVersion creates an SSL context that is specific to the provided
// SSL version. See http://www.openssl.org/docs/ssl/SSL_CTX_new.html for more.
func NewCtxWithVersion(version SSLVersion) (*Ctx, error) {
	var method *C.SSL_METHOD
	switch version {
	case SSLv3:
		method = C.SSLv3_method()
	case TLSv1:
		method = C.TLSv1_method()
	case TLSv1_1:
		method = C.OUR_TLSv1_1_method()
	case TLSv1_2:
		method = C.OUR_TLSv1_2_method()
	case AnyVersion:
		method = C.SSLv23_method()
	}
	if method == nil {
		return nil, errors.New("unknown ssl/tls version")
	}
	return newCtx(method)
}

// NewCtx creates a context that supports any TLS version 1.0 and newer.
func NewCtx() (*Ctx, error) {
	c, err := NewCtxWithVersion(AnyVersion)
	if err == nil {
		c.SetOptions(NoSSLv2 | NoSSLv3)
	}
	return c, err
}

// NewCtxFromFiles calls NewCtx, loads the provided files, and configures the
// context to use them.
func NewCtxFromFiles(cert_file string, key_file string) (*Ctx, error) {
	ctx, err := NewCtx()
	if err != nil {
		return nil, err
	}

	cert_bytes, err := ioutil.ReadFile(cert_file)
	if err != nil {
		return nil, err
	}

	cert, err := LoadCertificateFromPEM(cert_bytes)
	if err != nil {
		return nil, err
	}

	err = ctx.UseCertificate(cert)
	if err != nil {
		return nil, err
	}

	key_bytes, err := ioutil.ReadFile(key_file)
	if err != nil {
		return nil, err
	}

	key, err := LoadPrivateKeyFromPEM(key_bytes)
	if err != nil {
		return nil, err
	}

	err = ctx.UsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return ctx, nil
}

// NewCtxFromFilesTickets calls NewCtxFromFiles, loads the provided files, and 
// configures the context to use them with TLS Tikets rfc5077.
func NewCtxFromFilesTickets(cert_file, key_file string, ticket_files []string) (*Ctx, error) {
	if hasOpenSSLNoTLSExt() || getOpenSSLVersion() < 0x0090800f {
		return nil, errors.New("There is no support TLS tickets in your OpenSSL version")
	}

	ctx, err := NewCtxFromFiles(cert_file, key_file)
	if err != nil {
		return nil, err
	}

	if len(ticket_files) < 1 {
		return nil, errors.New("There are no TLS tickets")
	}

	tickets := make([]*TLSTicket, len(ticket_files))

	for i, ticket_file := range ticket_files {
		ticketBytes, err := ioutil.ReadFile(ticket_file)
		if err != nil {
			return nil, err
		}

		ticket, err := NewTLSTicket(ticketBytes)
		if err != nil {
			return nil, err
		}

		tickets[i] = ticket
	}

	if (C.SSL_CTX_set_tlsext_ticket_key_cb_not_a_macro(ctx.ctx, (*[0]byte)(C.ticket_cb)) == 0) {
		return nil, errors.New("Session Tickets are not available. Please check your version of openssl")
	}
	
	ctx.tickets = tickets
	
	return ctx, nil
}

// EllipticCurve repesents the ASN.1 OID of an elliptic curve.
// see https://www.openssl.org/docs/apps/ecparam.html for a list of implemented curves.
type EllipticCurve int

const (
	// P-256: X9.62/SECG curve over a 256 bit prime field
	Prime256v1 EllipticCurve = C.NID_X9_62_prime256v1
	// P-384: NIST/SECG curve over a 384 bit prime field
	Secp384r1 EllipticCurve = C.NID_secp384r1
)

// SetEllipticCurve sets the elliptic curve used by the SSL context to
// enable an ECDH cipher suite to be selected during the handshake.
func (c *Ctx) SetEllipticCurve(curve EllipticCurve) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	k := C.EC_KEY_new_by_curve_name(C.int(curve))
	if k == nil {
		return errors.New("Unknown curve")
	}
	defer C.EC_KEY_free(k)

	if int(C.SSL_CTX_set_tmp_ecdh_not_a_macro(c.ctx, k)) != 1 {
		return errorFromErrorQueue()
	}

	return nil
}

// UseCertificate configures the context to present the given certificate to
// peers.
func (c *Ctx) UseCertificate(cert *Certificate) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if int(C.SSL_CTX_use_certificate(c.ctx, cert.x)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

// AddChainCertificate adds a certificate to the chain presented in the
// handshake.
func (c *Ctx) AddChainCertificate(cert *Certificate) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if int(C.SSL_CTX_add_extra_chain_cert_not_a_macro(c.ctx, cert.x)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

// UsePrivateKey configures the context to use the given private key for SSL
// handshakes.
func (c *Ctx) UsePrivateKey(key PrivateKey) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if int(C.SSL_CTX_use_PrivateKey(c.ctx, key.evpPKey())) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

type CertificateStore struct {
	store *C.X509_STORE
	ctx   *Ctx // for gc
}

// GetCertificateStore returns the context's certificate store that will be
// used for peer validation.
func (c *Ctx) GetCertificateStore() *CertificateStore {
	// we don't need to dealloc the cert store pointer here, because it points
	// to a ctx internal. so we do need to keep the ctx around
	return &CertificateStore{
		store: C.SSL_CTX_get_cert_store(c.ctx),
		ctx:   c}
}

// AddCertificate marks the provided Certificate as a trusted certificate in
// the given CertificateStore.
func (s *CertificateStore) AddCertificate(cert *Certificate) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if int(C.X509_STORE_add_cert(s.store, cert.x)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

type CertificateStoreCtx struct {
	ctx     *C.X509_STORE_CTX
	ssl_ctx *Ctx
}

func (self *CertificateStoreCtx) Err() error {
	code := C.X509_STORE_CTX_get_error(self.ctx)
	if code == C.X509_V_OK {
		return nil
	}
	return fmt.Errorf("openssl: %s",
		C.GoString(C.X509_verify_cert_error_string(C.long(code))))
}

func (self *CertificateStoreCtx) Depth() int {
	return int(C.X509_STORE_CTX_get_error_depth(self.ctx))
}

// the certicate returned is only valid for the lifetime of the underlying
// X509_STORE_CTX
func (self *CertificateStoreCtx) GetCurrentCert() *Certificate {
	x509 := C.X509_STORE_CTX_get_current_cert(self.ctx)
	if x509 == nil {
		return nil
	}
	// add a ref
	C.CRYPTO_add_not_a_macro(&x509.references, 1, C.CRYPTO_LOCK_X509)
	cert := &Certificate{
		x: x509,
	}
	runtime.SetFinalizer(cert, func(cert *Certificate) {
		C.X509_free(cert.x)
	})
	return cert
}

// LoadVerifyLocations tells the context to trust all certificate authorities
// provided in either the ca_file or the ca_path.
// See http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html for
// more.
func (c *Ctx) LoadVerifyLocations(ca_file string, ca_path string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var c_ca_file, c_ca_path *C.char
	if ca_file != "" {
		c_ca_file = C.CString(ca_file)
		defer C.free(unsafe.Pointer(c_ca_file))
	}
	if ca_path != "" {
		c_ca_path = C.CString(ca_path)
		defer C.free(unsafe.Pointer(c_ca_path))
	}
	if C.SSL_CTX_load_verify_locations(c.ctx, c_ca_file, c_ca_path) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

type Options int

const (
	// NoCompression is only valid if you are using OpenSSL 1.0.1 or newer
	NoCompression                      Options = C.SSL_OP_NO_COMPRESSION
	NoSSLv2                            Options = C.SSL_OP_NO_SSLv2
	NoSSLv3                            Options = C.SSL_OP_NO_SSLv3
	NoTLSv1                            Options = C.SSL_OP_NO_TLSv1
	CipherServerPreference             Options = C.SSL_OP_CIPHER_SERVER_PREFERENCE
	NoSessionResumptionOrRenegotiation Options = C.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	NoTicket                           Options = C.SSL_OP_NO_TICKET
)

// SetOptions sets context options. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
func (c *Ctx) SetOptions(options Options) Options {
	return Options(C.SSL_CTX_set_options_not_a_macro(
		c.ctx, C.long(options)))
}

type Modes int

const (
	// ReleaseBuffers is only valid if you are using OpenSSL 1.0.1 or newer
	ReleaseBuffers Modes = C.SSL_MODE_RELEASE_BUFFERS
)

// SetMode sets context modes. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_mode.html
func (c *Ctx) SetMode(modes Modes) Modes {
	return Modes(C.SSL_CTX_set_mode_not_a_macro(c.ctx, C.long(modes)))
}

// GetMode returns context modes. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_mode.html
func (c *Ctx) GetMode() Modes {
	return Modes(C.SSL_CTX_get_mode_not_a_macro(c.ctx))
}

type VerifyOptions int

const (
	VerifyNone             VerifyOptions = C.SSL_VERIFY_NONE
	VerifyPeer             VerifyOptions = C.SSL_VERIFY_PEER
	VerifyFailIfNoPeerCert VerifyOptions = C.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	VerifyClientOnce       VerifyOptions = C.SSL_VERIFY_CLIENT_ONCE
)

type VerifyCallback func(ok bool, store *CertificateStoreCtx) bool

//export verify_cb_thunk
func verify_cb_thunk(p unsafe.Pointer, ok C.int, ctx *C.X509_STORE_CTX) C.int {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: verify callback panic'd: %v", err)
			os.Exit(1)
		}
	}()
	verify_cb := (*Ctx)(p).verify_cb
	// set up defaults just in case verify_cb is nil
	if verify_cb != nil {
		store := &CertificateStoreCtx{ctx: ctx}
		if verify_cb(ok == 1, store) {
			ok = 1
		} else {
			ok = 0
		}
	}
	return ok
}

// SetVerify controls peer verification settings. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (c *Ctx) SetVerify(options VerifyOptions, verify_cb VerifyCallback) {
	c.verify_cb = verify_cb
	if verify_cb != nil {
		C.SSL_CTX_set_verify(c.ctx, C.int(options), (*[0]byte)(C.verify_cb))
	} else {
		C.SSL_CTX_set_verify(c.ctx, C.int(options), nil)
	}
}

func (c *Ctx) SetVerifyMode(options VerifyOptions) {
	c.SetVerify(options, c.verify_cb)
}

func (c *Ctx) SetVerifyCallback(verify_cb VerifyCallback) {
	c.SetVerify(c.VerifyMode(), verify_cb)
}

func (c *Ctx) VerifyMode() VerifyOptions {
	return VerifyOptions(C.SSL_CTX_get_verify_mode(c.ctx))
}

// SetVerifyDepth controls how many certificates deep the certificate
// verification logic is willing to follow a certificate chain. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (c *Ctx) SetVerifyDepth(depth int) {
	C.SSL_CTX_set_verify_depth(c.ctx, C.int(depth))
}

func (c *Ctx) SetSessionId(session_id []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var ptr *C.uchar
	if len(session_id) > 0 {
		ptr = (*C.uchar)(unsafe.Pointer(&session_id[0]))
	}
	if int(C.SSL_CTX_set_session_id_context(c.ctx, ptr,
		C.uint(len(session_id)))) == 0 {
		return errorFromErrorQueue()
	}
	return nil
}

// SetCipherList sets the list of available ciphers. The format of the list is
// described at http://www.openssl.org/docs/apps/ciphers.html, but see
// http://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html for more.
func (c *Ctx) SetCipherList(list string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	clist := C.CString(list)
	defer C.free(unsafe.Pointer(clist))
	if int(C.SSL_CTX_set_cipher_list(c.ctx, clist)) == 0 {
		return errorFromErrorQueue()
	}
	return nil
}

type SessionCacheModes int

const (
	SessionCacheOff    SessionCacheModes = C.SSL_SESS_CACHE_OFF
	SessionCacheClient SessionCacheModes = C.SSL_SESS_CACHE_CLIENT
	SessionCacheServer SessionCacheModes = C.SSL_SESS_CACHE_SERVER
	SessionCacheBoth   SessionCacheModes = C.SSL_SESS_CACHE_BOTH
	NoAutoClear        SessionCacheModes = C.SSL_SESS_CACHE_NO_AUTO_CLEAR
	NoInternalLookup   SessionCacheModes = C.SSL_SESS_CACHE_NO_INTERNAL_LOOKUP
	NoInternalStore    SessionCacheModes = C.SSL_SESS_CACHE_NO_INTERNAL_STORE
	NoInternal         SessionCacheModes = C.SSL_SESS_CACHE_NO_INTERNAL
)

// SetSessionCacheMode enables or disables session caching. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_session_cache_mode.html
func (c *Ctx) SetSessionCacheMode(modes SessionCacheModes) SessionCacheModes {
	return SessionCacheModes(
		C.SSL_CTX_set_session_cache_mode_not_a_macro(c.ctx, C.long(modes)))
}

//export ticket_cb_thunk
func ticket_cb_thunk(p unsafe.Pointer, con *C.SSL, key_name unsafe.Pointer, iv *C.uchar,
		          ectx *C.EVP_CIPHER_CTX, hctx *C.HMAC_CTX, enc C.int) C.int {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: ticket callback panic'd: %v", err)
			os.Exit(1)
		}
	}()

	ssl_ctx := C.SSL_get_SSL_CTX(con)
	ctx := (*Ctx)(unsafe.Pointer(C.SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx())))

	if (enc == 1) {
		// encrypt session ticket 
		C.RAND_bytes(iv, 16)
		C.EVP_EncryptInit_ex(ectx, C.EVP_aes_128_cbc(), nil, (*C.uchar)(unsafe.Pointer(&ctx.tickets[0].aes[0])), iv)
		C.HMAC_Init_ex(hctx, unsafe.Pointer(&ctx.tickets[0].hmac[0]), 16, C.tls_session_ticket_md(), nil)
		C.memcpy(key_name, unsafe.Pointer(&ctx.tickets[0].name[0]), 16)
		
		logger.Debugf("session ticket encrypt key: %x, enc: %d", ctx.tickets[0].name, enc)

		// run callback	
		if ctx.ticket_cb != nil {
			ctx.ticket_cb(TLSTicketResume)
		}
		return C.int(TLSTicketResume)

	} else {
		// decrypt session ticket
		i := -1
		for j, ticket := range ctx.tickets  {
			if bytes.Equal(ticket.name, C.GoBytes(key_name, 16)) {
				i = j
				goto Found
			}
        }

        logger.Debugf("session ticket decrypt key not found: %x, enc: %d", C.GoBytes(key_name, 16), enc)

        // run callback	
		if ctx.ticket_cb != nil {
			ctx.ticket_cb(TLSTicketError)
		}
        return C.int(TLSTicketError)

    Found:

        logger.Debugf("session ticket decrypt key: %x, key_id: %d, enc: %d", ctx.tickets[i].name, i, enc)

		C.HMAC_Init_ex(hctx, unsafe.Pointer(&ctx.tickets[i].hmac[0]), 16, C.tls_session_ticket_md(), nil);
        C.EVP_DecryptInit_ex(ectx, C.EVP_aes_128_cbc(), nil, (*C.uchar)(unsafe.Pointer(&ctx.tickets[i].aes[0])), iv);
		
		if i == 0 {
			// run callback	
			if ctx.ticket_cb != nil {
				ctx.ticket_cb(TLSTicketResume)
			}
			return C.int(TLSTicketResume)
		}
		// run callback	
		if ctx.ticket_cb != nil {
			ctx.ticket_cb(TLSTicketRenew)
		}
		return C.int(TLSTicketRenew)
	}
}

// SetTicketCallback set tls ticket callback function.
// See more about tls ticket http://www.ietf.org/rfc/rfc5077.
func (c *Ctx) SetTicketCallback(ticket_cb TLSTicketCallback) {
	c.ticket_cb = ticket_cb	
}
