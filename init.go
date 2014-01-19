// Copyright (C) 2014 Space Monkey, Inc.

// Package openssl is a light wrapper around OpenSSL for Go.
// It strives to provide a near-drop-in replacement for the Go standard library
// tls package, while allowing for:
//  * Performance - OpenSSL is battle-tested and optimized C. While Go's built-
//    in library shows great promise, it is still young and in some places,
//    inefficient. This simple OpenSSL wrapper can often do at least 2x with
//    the same cipher and protocol.
//
//    On my lappytop, I get the following speeds for AES128-SHA
//      BenchmarkStdlibThroughput      50000     58685 ns/op    17.45 MB/s
//      BenchmarkOpenSSLThroughput    100000     20772 ns/op    49.30 MB/s
//
//  * Interoperability - many systems support OpenSSL with a variety of plugins
//    and modules for things, such as hardware acceleration in embedded devices
//
//  * Greater flexibility and configuration - OpenSSL allows for far greater
//    configuration of corner cases and backwards compatibility (such as
//    support of SSLv2)
//
//  * Security - OpenSSL has been reviewed by security experts thoroughly.
//    According to its author, the same can not be said of the standard
//    library. Though this wrapper has not received equal scrutiny, it is very
//    small and easy to check.
//
// Starting an HTTP server that uses OpenSSL is very easy. It's as simple as:
//  log.Fatal(openssl.ListenAndServeTLS(
//          ":8443", "my_server.crt", "my_server.key", myHandler))
//
// Getting a net.Listener that uses OpenSSL is also easy:
//  ctx, err := openssl.NewCtxFromFiles("my_server.crt", "my_server.key")
//  if err != nil {
//          log.Fatal(err)
//  }
//  l, err := openssl.Listen("tcp", ":7777", ctx)
//
// Making a client connection is straightforward too:
//  ctx, err := NewCtx()
//  if err != nil {
//          log.Fatal(err)
//  }
//  err = ctx.LoadVerifyLocations("/etc/ssl/certs/ca-certificates.crt", "")
//  if err != nil {
//          log.Fatal(err)
//  }
//  conn, err := openssl.Dial("tcp", "localhost:7777", ctx, 0)
//
// TODO/Help wanted: make an easy interface to the net/http client library
package openssl

/*
#cgo pkg-config: openssl
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

extern void sslThreadId(CRYPTO_THREADID *id);
extern void sslMutexOp(int mode, int n, char *file, int line);

static void OpenSSL_add_all_algorithms_not_a_macro() {
  OpenSSL_add_all_algorithms();
}
*/
import "C"

import (
    "errors"
    "fmt"
    "strings"
    "sync"

    "code.spacemonkey.com/go/openssl/utils"
)

var (
    sslMutexes []sync.Mutex
)

func init() {
    C.OPENSSL_config(nil)
    C.ENGINE_load_builtin_engines()
    C.SSL_load_error_strings()
    C.SSL_library_init()
    C.OpenSSL_add_all_algorithms_not_a_macro()
    sslMutexes = make([]sync.Mutex, int(C.CRYPTO_num_locks()))
    C.CRYPTO_THREADID_set_callback((*[0]byte)(C.sslThreadId))
    C.CRYPTO_set_locking_callback((*[0]byte)(C.sslMutexOp))

    // TODO: support dynlock callbacks
}

// errorFromErrorQueue needs to run in the same OS thread as the operation
// that caused the possible error
func errorFromErrorQueue() error {
    var errs []string
    for {
        err := C.ERR_get_error()
        if err == 0 {
            break
        }
        errs = append(errs, fmt.Sprintf("%s:%s:%s",
            C.GoString(C.ERR_lib_error_string(err)),
            C.GoString(C.ERR_func_error_string(err)),
            C.GoString(C.ERR_reason_error_string(err))))
    }
    return errors.New(fmt.Sprintf("SSL errors: %s", strings.Join(errs, "\n")))
}

//export sslMutexOp
func sslMutexOp(mode, n C.int, file *C.char, line C.int) {
    if mode&C.CRYPTO_LOCK > 0 {
        sslMutexes[n].Lock()
    } else {
        sslMutexes[n].Unlock()
    }
}

//export sslThreadId
func sslThreadId(id *C.CRYPTO_THREADID) {
    C.CRYPTO_THREADID_set_pointer(id, utils.ThreadId())
}
