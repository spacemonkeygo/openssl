// Copyright (C) 2014 Space Monkey, Inc.
// +build cgo,!darwin

package openssl

// #include <openssl/evp.h>
import "C"

import (
	"errors"
	"fmt"
)

type AuthenticatedEncryptionCipherCtx interface {
	EncryptionCipherCtx

	// data passed in to ExtraData() is part of the final output; it is
	// not encrypted itself, but is part of the authenticated data. when
	// decrypting or authenticating, pass back with the decryption
	// context's ExtraData()
	ExtraData([]byte) error

	// use after finalizing encryption to get the authenticating tag
	GetTag() ([]byte, error)
}

type AuthenticatedDecryptionCipherCtx interface {
	DecryptionCipherCtx

	// pass in any extra data that was added during encryption with the
	// encryption context's ExtraData()
	ExtraData([]byte) error

	// use before finalizing decryption to tell the library what the
	// tag is expected to be
	SetTag([]byte) error
}

type authEncryptionCipherCtx struct {
	*encryptionCipherCtx
}

type authDecryptionCipherCtx struct {
	*decryptionCipherCtx
}

func getGCMCipher(blocksize int) (*Cipher, error) {
	var cipherptr *C.EVP_CIPHER
	switch blocksize {
	case 256:
		cipherptr = C.EVP_aes_256_gcm()
	case 192:
		cipherptr = C.EVP_aes_192_gcm()
	case 128:
		cipherptr = C.EVP_aes_128_gcm()
	default:
		return nil, fmt.Errorf("unknown block size %d", blocksize)
	}
	return &Cipher{ptr: cipherptr}, nil
}

func NewGCMEncryptionCipherCtx(blocksize int, e *Engine, key, iv []byte) (
	AuthenticatedEncryptionCipherCtx, error) {
	cipher, err := getGCMCipher(blocksize)
	if err != nil {
		return nil, err
	}
	ctx, err := newEncryptionCipherCtx(cipher, e, key, nil)
	if err != nil {
		return nil, err
	}
	if iv != nil {
		err := ctx.setCtrl(C.EVP_CTRL_GCM_SET_IVLEN, len(iv))
		if err != nil {
			return nil, fmt.Errorf("could not set IV len to %d: %s",
				len(iv), err)
		}
		if 1 != C.EVP_EncryptInit_ex(ctx.ctx, nil, nil, nil,
			(*C.uchar)(&iv[0])) {
			return nil, errors.New("failed to apply IV")
		}
	}
	return &authEncryptionCipherCtx{encryptionCipherCtx: ctx}, nil
}

func NewGCMDecryptionCipherCtx(blocksize int, e *Engine, key, iv []byte) (
	AuthenticatedDecryptionCipherCtx, error) {
	cipher, err := getGCMCipher(blocksize)
	if err != nil {
		return nil, err
	}
	ctx, err := newDecryptionCipherCtx(cipher, e, key, nil)
	if err != nil {
		return nil, err
	}
	if iv != nil {
		err := ctx.setCtrl(C.EVP_CTRL_GCM_SET_IVLEN, len(iv))
		if err != nil {
			return nil, fmt.Errorf("could not set IV len to %d: %s",
				len(iv), err)
		}
		if 1 != C.EVP_DecryptInit_ex(ctx.ctx, nil, nil, nil,
			(*C.uchar)(&iv[0])) {
			return nil, errors.New("failed to apply IV")
		}
	}
	return &authDecryptionCipherCtx{decryptionCipherCtx: ctx}, nil
}

func (ctx *authEncryptionCipherCtx) ExtraData(aad []byte) error {
	if aad == nil {
		return nil
	}
	var outlen C.int
	if 1 != C.EVP_EncryptUpdate(ctx.ctx, nil, &outlen, (*C.uchar)(&aad[0]),
		C.int(len(aad))) {
		return errors.New("failed to add additional authenticated data")
	}
	return nil
}

func (ctx *authDecryptionCipherCtx) ExtraData(aad []byte) error {
	if aad == nil {
		return nil
	}
	var outlen C.int
	if 1 != C.EVP_DecryptUpdate(ctx.ctx, nil, &outlen, (*C.uchar)(&aad[0]),
		C.int(len(aad))) {
		return errors.New("failed to add additional authenticated data")
	}
	return nil
}

func (ctx *authEncryptionCipherCtx) GetTag() ([]byte, error) {
	return ctx.getCtrlBytes(C.EVP_CTRL_GCM_GET_TAG, GCM_TAG_MAXLEN,
		GCM_TAG_MAXLEN)
}

func (ctx *authDecryptionCipherCtx) SetTag(tag []byte) error {
	return ctx.setCtrlBytes(C.EVP_CTRL_GCM_SET_TAG, len(tag), tag)
}
