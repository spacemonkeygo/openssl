package openssl

// #include "shim.h"
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

// DigestComputer is a generic structure to compute message digest
// with any hash function supported by OpenSSL
type DigestComputer struct {
	ctx    *C.EVP_MD_CTX
	engine *Engine
	evpMD  EVP_MD
}

func NewDigestComputer(digestType EVP_MD) (*DigestComputer, error) {
	return NewDigestComputerWithEngine(nil, digestType)
}

func NewDigestComputerWithEngine(e *Engine, digestType EVP_MD) (*DigestComputer, error) {
	hash := &DigestComputer{engine: e, evpMD: digestType}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, fmt.Errorf("openssl: %s: unable to allocate ctx", digestType.String())
	}
	runtime.SetFinalizer(hash, func(hash *DigestComputer) { hash.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}
	return hash, nil
}

func (s *DigestComputer) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *DigestComputer) Reset() error {
	if 1 != C.X_EVP_DigestInit_ex(s.ctx, s.evpMD.c(), engineRef(s.engine)) {
		return fmt.Errorf("openssl: %v: cannot init evpMD ctx", s.evpMD.String())
	}
	return nil
}

func (s *DigestComputer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&p[0]),
		C.size_t(len(p))) {
		return 0, fmt.Errorf("openssl: %v: cannot update evpMD", s.evpMD.String())
	}
	return len(p), nil
}

func (s *DigestComputer) Sum() ([]byte, error) {
	result := make([]byte, s.evpMD.Size())
	if 1 != C.X_EVP_DigestFinal_ex(s.ctx,
		(*C.uchar)(unsafe.Pointer(&result[0])), nil) {
		return result, fmt.Errorf("openssl: %v: cannot finalize ctx", s.evpMD.String())
	}
	return result, s.Reset()
}
