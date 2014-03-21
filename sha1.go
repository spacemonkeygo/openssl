// Copyright (C) 2014 Space Monkey, Inc.
// +build cgo

package openssl

/*
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "openssl/evp.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type SHA1Hash struct {
	ctx C.EVP_MD_CTX
}

func NewSHA1Hash() (*SHA1Hash, error) {
	hash := new(SHA1Hash)
	C.EVP_MD_CTX_init(&hash.ctx)
	runtime.SetFinalizer(hash, func(h *SHA1Hash) { h.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}
	return hash, nil
}

func (s *SHA1Hash) Close() {
	C.EVP_MD_CTX_cleanup(&s.ctx)
}

func (s *SHA1Hash) Reset() error {
	if 1 != C.EVP_DigestInit_ex(&s.ctx, C.EVP_sha1(), nil) {
		return errors.New("openssl: sha1: cannot init digest ctx")
	}
	return nil
}

func (s *SHA1Hash) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.EVP_DigestUpdate(&s.ctx, unsafe.Pointer(&p[0]),
		C.size_t(len(p))) {
		return 0, errors.New("openssl: sha1: cannot update digest")
	}
	return len(p), nil
}

func (s *SHA1Hash) Sum() (result [20]byte, err error) {
	if 1 != C.EVP_DigestFinal_ex(&s.ctx,
		(*C.uchar)(unsafe.Pointer(&result[0])), nil) {
		return result, errors.New("openssl: sha1: cannot finalize ctx")
	}
	return result, s.Reset()
}

func SHA1(data []byte) (result [20]byte, err error) {
	hash, err := NewSHA1Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	return hash.Sum()
}
