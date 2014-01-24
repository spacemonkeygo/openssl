// Copyright (C) 2014 Space Monkey, Inc.

package openssl

// #include <openssl/ssl.h>
// #include <openssl/conf.h>
//
// long SSL_CTX_set_options_not_a_macro(SSL_CTX* ctx, long options) {
//    return SSL_CTX_set_options(ctx, options);
// }
//
// long SSL_CTX_set_mode_not_a_macro(SSL_CTX* ctx, long modes) {
//    return SSL_CTX_set_mode(ctx, modes);
// }
//
// long SSL_CTX_set_session_cache_mode_not_a_macro(SSL_CTX* ctx, long modes) {
//    return SSL_CTX_set_session_cache_mode(ctx, modes);
// }
//
// #ifndef SSL_MODE_RELEASE_BUFFERS
// #define SSL_MODE_RELEASE_BUFFERS 0
// #endif
// #ifndef SSL_OP_NO_COMPRESSION
// #define SSL_OP_NO_COMPRESSION 0
// #endif
// #ifndef TLSv1_1_method
// const SSL_METHOD *TLSv1_1_method() { return NULL; }
// #endif
// #ifndef TLSv1_2_method
// const SSL_METHOD *TLSv1_2_method() { return NULL; }
// #endif
import "C"

import (
    "errors"
    "io/ioutil"
    "runtime"
    "unsafe"
)

type Ctx struct {
    ctx *C.SSL_CTX
}

func newCtx(method *C.SSL_METHOD) (*Ctx, error) {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    ctx := C.SSL_CTX_new(method)
    if ctx == nil {
        return nil, errorFromErrorQueue()
    }
    c := &Ctx{ctx: ctx}
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
        method = C.TLSv1_1_method()
    case TLSv1_2:
        method = C.TLSv1_2_method()
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

    cert, err := LoadCertificate(cert_bytes)
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

    key, err := LoadPrivateKey(key_bytes)
    if err != nil {
        return nil, err
    }

    err = ctx.UsePrivateKey(key)
    if err != nil {
        return nil, err
    }

    return ctx, nil
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

type VerifyOptions int

const (
    VerifyNone             VerifyOptions = C.SSL_VERIFY_NONE
    VerifyPeer             VerifyOptions = C.SSL_VERIFY_PEER
    VerifyFailIfNoPeerCert VerifyOptions = C.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    VerifyClientOnce       VerifyOptions = C.SSL_VERIFY_CLIENT_ONCE
)

// SetVerify controls peer verification settings. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (c *Ctx) SetVerify(options VerifyOptions) {
    // TODO: take a callback
    C.SSL_CTX_set_verify(c.ctx, C.int(options), nil)
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
    if int(C.SSL_CTX_set_session_id_context(c.ctx,
        (*C.uchar)(unsafe.Pointer(&session_id[0])),
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
