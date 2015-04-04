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
#include <openssl/opensslv.h>

static const int SSL_HAS_TLSEXT() {
#if ! defined OPENSSL_NO_TLSEXT
    return 1;
#else
    return 0;
#endif
}
*/
import "C"

func getOpenSSLVersion() int {
	return int(C.OPENSSL_VERSION_NUMBER)
}

func hasOpenSSLNoTLSExt() bool {
	if int(C.SSL_HAS_TLSEXT()) == 1 {
		return false
	}
	return true
}
