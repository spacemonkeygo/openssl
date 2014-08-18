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

static long SSL_CTX_set_tlsext_servername_callback_not_a_macro(SSL_CTX* ctx,  int (*cb)(SSL *con, int *ad, void *args)) {
	return SSL_CTX_set_tlsext_servername_callback(ctx, cb);
}

#if defined SSL_CTRL_SET_TLSEXT_HOSTNAME
	extern int sni_cb(SSL *ssl_conn, int *ad, void *arg);
#endif
*/
import "C"

import (
	"os"
	"unsafe"
)

type SSLTLSExtErr int

const (
	SSLTLSExtErrOK           SSLTLSExtErr = C.SSL_TLSEXT_ERR_OK
	SSLTLSExtErrAlertWarning SSLTLSExtErr = C.SSL_TLSEXT_ERR_ALERT_WARNING
	SSLTLSEXTErrAlertFatal   SSLTLSExtErr = C.SSL_TLSEXT_ERR_ALERT_FATAL
	SSLTLSEXTErrNoAck        SSLTLSExtErr = C.SSL_TLSEXT_ERR_NOACK
)

type SSL struct {
	ssl *C.SSL
}

func (s *SSL) GetServername() (string, error) {
	return C.GoString(C.SSL_get_servername(s.ssl, C.TLSEXT_NAMETYPE_host_name)), nil
}

func (s *SSL) SetSSLCtx(ctx *Ctx) {
	/*
	 * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
	 * adjust other things we care about
	 */
	C.SSL_set_SSL_CTX(s.ssl, ctx.ctx)
}

type TLSExtServernameCallback func(ssl *SSL) SSLTLSExtErr

func (c *Ctx) SetTLSExtServernameCallback(sni_cb TLSExtServernameCallback) {
	c.sni_cb = sni_cb
	C.SSL_CTX_set_tlsext_servername_callback_not_a_macro(c.ctx, (*[0]byte)(C.sni_cb))
}

//export sni_cb_thunk
func sni_cb_thunk(p unsafe.Pointer, con *C.SSL, ad unsafe.Pointer, arg unsafe.Pointer) C.int {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: verify callback sni panic'd: %v", err)
			os.Exit(1)
		}
	}()

	sni_cb := (*Ctx)(p).sni_cb
	ssl := &SSL{ssl: con}

	return C.int(sni_cb(ssl))
}
