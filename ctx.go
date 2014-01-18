// Copyright (C) 2014 Space Monkey, Inc.

package openssl

// #cgo pkg-config: openssl
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
import "C"

import (
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

func NewCtxWithVersion(version SSLVersion) (*Ctx, error) {
    switch version {
    case SSLv3:
        return newCtx(C.SSLv3_method())
    case TLSv1:
        return newCtx(C.TLSv1_method())
    case TLSv1_1:
        return newCtx(C.TLSv1_1_method())
    case TLSv1_2:
        return newCtx(C.TLSv1_2_method())
    case AnyVersion:
        return newCtx(C.SSLv23_method())
    default:
        return nil, SSLError.New("unknown version")
    }
}

func NewCtx() (*Ctx, error) {
    c, err := NewCtxWithVersion(AnyVersion)
    if err == nil {
        c.SetOptions(NoSSLv2 | NoSSLv3)
    }
    return c, err
}

func (c *Ctx) UseCertificate(cert *Certificate) error {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    if int(C.SSL_CTX_use_certificate(c.ctx, cert.x)) != 1 {
        return errorFromErrorQueue()
    }
    return nil
}

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

func (c *Ctx) GetCertificateStore() *CertificateStore {
    // we don't need to dealloc the cert store pointer here, because it points
    // to a ctx internal. so we do need to keep the ctx around
    return &CertificateStore{
        store: C.SSL_CTX_get_cert_store(c.ctx),
        ctx:   c}
}

func (s *CertificateStore) AddCertificate(cert *Certificate) error {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    if int(C.X509_STORE_add_cert(s.store, cert.x)) != 1 {
        return errorFromErrorQueue()
    }
    return nil
}

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
    NoCompression                      Options = C.SSL_OP_NO_COMPRESSION
    NoSSLv2                                    = C.SSL_OP_NO_SSLv2
    NoSSLv3                                    = C.SSL_OP_NO_SSLv3
    NoTLSv1                                    = C.SSL_OP_NO_TLSv1
    CipherServerPreference                     = C.SSL_OP_CIPHER_SERVER_PREFERENCE
    NoSessionResumptionOrRenegotiation         = C.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    NoTicket                                   = C.SSL_OP_NO_TICKET
)

func (c *Ctx) SetOptions(options Options) Options {
    return Options(C.SSL_CTX_set_options_not_a_macro(
        c.ctx, C.long(options)))
}

type Modes int

const (
    ReleaseBuffers Modes = C.SSL_MODE_RELEASE_BUFFERS
)

func (c *Ctx) SetMode(modes Modes) Modes {
    return Modes(C.SSL_CTX_set_mode_not_a_macro(c.ctx, C.long(modes)))
}

type VerifyOptions int

const (
    VerifyNone             VerifyOptions = C.SSL_VERIFY_NONE
    VerifyPeer                           = C.SSL_VERIFY_PEER
    VerifyFailIfNoPeerCert               = C.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    VerifyClientOnce                     = C.SSL_VERIFY_CLIENT_ONCE
)

func (c *Ctx) SetVerify(options VerifyOptions) {
    // TODO: take a callback
    C.SSL_CTX_set_verify(c.ctx, C.int(options), nil)
}

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
    SessionCacheClient                   = C.SSL_SESS_CACHE_CLIENT
    SessionCacheServer                   = C.SSL_SESS_CACHE_SERVER
    SessionCacheBoth                     = C.SSL_SESS_CACHE_BOTH
    NoAutoClear                          = C.SSL_SESS_CACHE_NO_AUTO_CLEAR
    NoInternalLookup                     = C.SSL_SESS_CACHE_NO_INTERNAL_LOOKUP
    NoInternalStore                      = C.SSL_SESS_CACHE_NO_INTERNAL_STORE
    NoInternal                           = C.SSL_SESS_CACHE_NO_INTERNAL
)

func (c *Ctx) SetSessionCacheMode(modes SessionCacheModes) SessionCacheModes {
    return SessionCacheModes(
        C.SSL_CTX_set_session_cache_mode_not_a_macro(c.ctx, C.long(modes)))
}
