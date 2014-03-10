#include <openssl/ssl.h>
#include "_cgo_export.h"
#include <stdio.h>

int verify_cb(int ok, X509_STORE_CTX* store) {
	SSL* ssl = (SSL *)X509_STORE_CTX_get_app_data(store);
	SSL_CTX* ssl_ctx = ssl_ctx = SSL_get_SSL_CTX(ssl);
	void* p = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	// get the pointer to the go Ctx object and pass it back into the thunk
	return verify_cb_thunk(p, ok, store);
}
