// +build cgo

package openssl

/*
#include <openssl/ssl.h>
*/
import "C"
import "runtime"

// FIPSModeSet enables a FIPS 140-2 validated mode of operation.
// https://wiki.openssl.org/index.php/FIPS_mode_set()
func FIPSModeSet(mode bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var r C.int
	if mode {
		r = C.FIPS_mode_set(1)
	} else {
		r = C.FIPS_mode_set(0)
	}
	if r != 1 {
		return errorFromErrorQueue()
	}
	return nil
}
