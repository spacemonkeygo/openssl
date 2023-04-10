// Copyright (C) 2017. See AUTHORS.
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

package openssl

/*
#include <shim.h>
*/
import "C"
import "runtime"

// FIPSModeSet enables a FIPS 140-2 validated mode of operation.
// OpenSSL 3.0.0 and greater - https://www.openssl.org/docs/man3.0/man3/EVP_default_properties_is_fips_enabled.html,
// lower than 3.0.0 - https://wiki.openssl.org/index.php/FIPS_mode_set()
func FIPSModeSet(mode bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var r C.int
	if mode {
		r = C.X_EVP_default_properties_enable_fips(nil, 1)
	} else {
		r = C.X_EVP_default_properties_enable_fips(nil, 0)
	}
	if r != 1 {
		return errorFromErrorQueue()
	}
	return nil
}
