// Copyright (C) 2014 Space Monkey, Inc.

package openssl

import (
    "net/http"
)

// ListenAndServeTLS will take an http.Handler and serve it using OpenSSL over
// the given tcp address, configured to use the provided cert and key files.
func ListenAndServeTLS(addr string, cert_file string, key_file string,
    handler http.Handler) error {
    return ServerListenAndServeTLS(
        &http.Server{Addr: addr, Handler: handler}, cert_file, key_file)
}

// ServerListenAndServeTLS will take an http.Server and serve it using OpenSSL
// configured to use the provided cert and key files.
func ServerListenAndServeTLS(srv *http.Server,
    cert_file, key_file string) error {
    addr := srv.Addr
    if addr == "" {
        addr = ":https"
    }

    ctx, err := NewCtxFromFiles(cert_file, key_file)
    if err != nil {
        return err
    }

    l, err := Listen("tcp", addr, ctx)
    if err != nil {
        return err
    }

    return srv.Serve(l)
}

// TODO: http client integration
// holy crap, getting this integrated nicely with the Go stdlib HTTP client
// stack so that it does proxying, connection pooling, and most importantly
// hostname verification is really hard. So much stuff is hardcoded to just use
// the built-in TLS lib. I think to get this to work either some crazy
// hacktackery beyond me, an almost straight up fork of the HTTP client, or
// serious stdlib internal refactoring is necessary.
// even more so, good luck getting openssl to use the operating system default
// root certificates if the user doesn't provide any. sadlol
// NOTE: if you're going to try and write your own round tripper, at least use
//  openssl.Dial, or equivalent logic
