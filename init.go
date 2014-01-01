// Copyright (C) 2014 Space Monkey, Inc.

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
    "fmt"
    "strings"
    "sync"

    "code.spacemonkey.com/go/errors"
    "code.spacemonkey.com/go/openssl/thread_id"
)

var (
    SSLError   = errors.New(nil, "SSL Error")
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
    var errors []string
    for {
        err := C.ERR_get_error()
        if err == 0 {
            break
        }
        errors = append(errors, fmt.Sprintf("%s:%s:%s",
            C.GoString(C.ERR_lib_error_string(err)),
            C.GoString(C.ERR_func_error_string(err)),
            C.GoString(C.ERR_reason_error_string(err))))
    }
    return SSLError.New("errors: %s", strings.Join(errors, "\n"))
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
    C.CRYPTO_THREADID_set_pointer(id, thread_id.Id())
}
