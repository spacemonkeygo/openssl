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

#include <openssl/ssl.h>
#include "_cgo_export.h"
#include <stdio.h>

int ticket_cb(SSL *con, unsigned char *key_name, unsigned char *iv,
		          EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc) {

 	SSL_CTX* ssl_ctx = ssl_ctx = SSL_get_SSL_CTX(con);
	void* p = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	return ticket_cb_thunk(p, con, key_name, iv, ctx, hctx, enc);
}
