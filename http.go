// Copyright (C) 2014 Space Monkey, Inc.

package openssl

import (
    "io/ioutil"
    "net/http"
)

func ListenAndServeTLS(addr string, cert_file string, key_file string,
    handler http.Handler) error {
    return ServerListenAndServeTLS(
        &http.Server{Addr: addr, Handler: handler}, cert_file, key_file)
}

func ServerListenAndServeTLS(srv *http.Server,
    cert_file, key_file string) error {
    addr := srv.Addr
    if addr == "" {
        addr = ":https"
    }

    ctx, err := NewCtx()
    if err != nil {
        return err
    }

    key_bytes, err := ioutil.ReadFile(key_file)
    if err != nil {
        return err
    }

    key, err := LoadPrivateKey(key_bytes)
    if err != nil {
        return err
    }

    err = ctx.UsePrivateKey(key)
    if err != nil {
        return err
    }

    cert_bytes, err := ioutil.ReadFile(cert_file)
    if err != nil {
        return err
    }

    cert, err := LoadCertificate(cert_bytes)
    if err != nil {
        return err
    }

    err = ctx.UseCertificate(cert)
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
