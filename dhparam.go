// +build cgo

package openssl

// #include "shim.h"
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type DH struct {
	dh *C.struct_dh_st
}

// LoadDHParametersFromPEM loads the Diffie-Hellman parameters from
// a PEM-encoded block.
func LoadDHParametersFromPEM(pem_block []byte) (*DH, error) {
	if len(pem_block) == 0 {
		return nil, errors.New("empty pem block")
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem_block[0]),
		C.int(len(pem_block)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	params := C.PEM_read_bio_DHparams(bio, nil, nil, nil)
	if params == nil {
		return nil, errors.New("failed reading dh parameters")
	}
	dhparams := &DH{dh: params}
	runtime.SetFinalizer(dhparams, func(dhparams *DH) {
		C.DH_free(dhparams.dh)
	})
	return dhparams, nil
}

// SetDHParameters sets the DH group (DH parameters) used to
// negotiate an emphemeral DH key during handshaking.
func (c *Ctx) SetDHParameters(dh *DH) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if int(C.X_SSL_CTX_set_tmp_dh(c.ctx, dh.dh)) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}
