// Copyright (C) 2014 Space Monkey, Inc.
// +build cgo

package openssl

// #include <openssl/evp.h>
//
// int EVP_CIPHER_block_size_not_a_macro(EVP_CIPHER *c) {
//     return EVP_CIPHER_block_size(c);
// }
//
// int EVP_CIPHER_key_length_not_a_macro(EVP_CIPHER *c) {
//     return EVP_CIPHER_key_length(c);
// }
//
// int EVP_CIPHER_iv_length_not_a_macro(EVP_CIPHER *c) {
//     return EVP_CIPHER_iv_length(c);
// }
//
// int EVP_CIPHER_nid_not_a_macro(EVP_CIPHER *c) {
//     return EVP_CIPHER_nid(c);
// }
//
// int EVP_CIPHER_CTX_block_size_not_a_macro(EVP_CIPHER_CTX *ctx) {
//     return EVP_CIPHER_CTX_block_size(ctx);
// }
//
// int EVP_CIPHER_CTX_key_length_not_a_macro(EVP_CIPHER_CTX *ctx) {
//     return EVP_CIPHER_CTX_key_length(ctx);
// }
//
// int EVP_CIPHER_CTX_iv_length_not_a_macro(EVP_CIPHER_CTX *ctx) {
//     return EVP_CIPHER_CTX_iv_length(ctx);
// }
//
// const EVP_CIPHER *EVP_CIPHER_CTX_cipher_not_a_macro(EVP_CIPHER_CTX *ctx) {
//     return EVP_CIPHER_CTX_cipher(ctx);
// }
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

const (
	GCM_TAG_MAXLEN = 16
)

type Cipher struct {
	ptr *C.EVP_CIPHER
}

type cipherCtx struct {
	ctx *C.EVP_CIPHER_CTX
}

type encryptionCipherCtx struct {
	cipherCtx
}

type decryptionCipherCtx struct {
	cipherCtx
}

type CipherCtx interface {
	Cipher() *Cipher
	BlockSize() int
	KeySize() int
	IVSize() int
}

type EncryptionCipherCtx interface {
	CipherCtx

	// pass in plaintext, get back ciphertext. can be called
	// multiple times as needed
	EncryptUpdate(input []byte) ([]byte, error)

	// call after all plaintext has been passed in; may return
	// additional ciphertext if needed to finish off a block
	// or extra padding information
	EncryptFinal() ([]byte, error)
}

type DecryptionCipherCtx interface {
	CipherCtx

	// pass in ciphertext, get back plaintext. can be called
	// multiple times as needed
	DecryptUpdate(input []byte) ([]byte, error)

	// call after all ciphertext has been passed in; may return
	// additional plaintext if needed to finish off a block
	DecryptFinal() ([]byte, error)
}

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

func Nid2ShortName(nid int) (string, error) {
	sn := C.OBJ_nid2sn(C.int(nid))
	if sn == nil {
		return "", fmt.Errorf("NID %d not found", nid)
	}
	return C.GoString(sn), nil
}

func GetCipherByName(name string) (*Cipher, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	p := C.EVP_get_cipherbyname(cname)
	if p == nil {
		return nil, fmt.Errorf("Cipher %v not found", name)
	}
	// we can consider ciphers to use static mem; don't need to free
	return &Cipher{ptr: p}, nil
}

func GetCipherByNid(nid int) (*Cipher, error) {
	sn, err := Nid2ShortName(nid)
	if err != nil {
		return nil, err
	}
	return GetCipherByName(sn)
}

func (c Cipher) Nid() int {
	return int(C.EVP_CIPHER_nid_not_a_macro(c.ptr))
}

func (c Cipher) ShortName() (string, error) {
	return Nid2ShortName(c.Nid())
}

func (c Cipher) BlockSize() int {
	return int(C.EVP_CIPHER_block_size_not_a_macro(c.ptr))
}

func (c Cipher) KeySize() int {
	return int(C.EVP_CIPHER_key_length_not_a_macro(c.ptr))
}

func (c Cipher) IVSize() int {
	return int(C.EVP_CIPHER_iv_length_not_a_macro(c.ptr))
}

func newCipherCtx() (*cipherCtx, error) {
	cctx := C.EVP_CIPHER_CTX_new()
	if cctx == nil {
		return nil, errors.New("failed to allocate cipher context")
	}
	ctx := &cipherCtx{cctx}
	runtime.SetFinalizer(ctx, func(ctx *cipherCtx) {
		C.EVP_CIPHER_CTX_free(ctx.ctx)
	})
	return ctx, nil
}

func (ctx *cipherCtx) applyKeyAndIV(key, iv []byte) error {
	var kptr, iptr *C.uchar
	if key != nil {
		if len(key) != ctx.KeySize() {
			return fmt.Errorf("bad key size (%d bytes instead of %d)",
				len(key), ctx.KeySize())
		}
		kptr = (*C.uchar)(&key[0])
	}
	if iv != nil {
		if len(iv) != ctx.IVSize() {
			return fmt.Errorf("bad IV size (%d bytes instead of %d)",
				len(iv), ctx.IVSize())
		}
		iptr = (*C.uchar)(&iv[0])
	}
	if kptr != nil || iptr != nil {
		if 1 != C.EVP_EncryptInit_ex(ctx.ctx, nil, nil, kptr, iptr) {
			return errors.New("failed to apply key/IV")
		}
	}
	return nil
}

func newEncryptionCipherCtx(c *Cipher, e *Engine, key, iv []byte) (
	*encryptionCipherCtx, error) {
	if c == nil {
		return nil, errors.New("null cipher not allowed")
	}
	ctx, err := newCipherCtx()
	if err != nil {
		return nil, err
	}
	var eptr *C.ENGINE
	if e != nil {
		eptr = e.e
	}
	if 1 != C.EVP_EncryptInit_ex(ctx.ctx, c.ptr, eptr, nil, nil) {
		return nil, errors.New("failed to initialize cipher context")
	}
	err = ctx.applyKeyAndIV(key, iv)
	if err != nil {
		return nil, err
	}
	return &encryptionCipherCtx{*ctx}, nil
}

func newDecryptionCipherCtx(c *Cipher, e *Engine, key, iv []byte) (
	*decryptionCipherCtx, error) {
	if c == nil {
		return nil, errors.New("null cipher not allowed")
	}
	ctx, err := newCipherCtx()
	if err != nil {
		return nil, err
	}
	var eptr *C.ENGINE
	if e != nil {
		eptr = e.e
	}
	if 1 != C.EVP_DecryptInit_ex(ctx.ctx, c.ptr, eptr, nil, nil) {
		return nil, errors.New("failed to initialize cipher context")
	}
	err = ctx.applyKeyAndIV(key, iv)
	if err != nil {
		return nil, err
	}
	return &decryptionCipherCtx{*ctx}, nil
}

func NewEncryptionCipherCtx(c *Cipher, e *Engine, key, iv []byte) (
	EncryptionCipherCtx, error) {
	return newEncryptionCipherCtx(c, e, key, iv)
}

func NewDecryptionCipherCtx(c *Cipher, e *Engine, key, iv []byte) (
	DecryptionCipherCtx, error) {
	return newDecryptionCipherCtx(c, e, key, iv)
}

func (ctx *cipherCtx) Cipher() *Cipher {
	return &Cipher{ptr: C.EVP_CIPHER_CTX_cipher_not_a_macro(ctx.ctx)}
}

func (ctx *cipherCtx) BlockSize() int {
	return int(C.EVP_CIPHER_CTX_block_size_not_a_macro(ctx.ctx))
}

func (ctx *cipherCtx) KeySize() int {
	return int(C.EVP_CIPHER_CTX_key_length_not_a_macro(ctx.ctx))
}

func (ctx *cipherCtx) IVSize() int {
	return int(C.EVP_CIPHER_CTX_iv_length_not_a_macro(ctx.ctx))
}

func (ctx *cipherCtx) setCtrl(code, arg int) error {
	res := C.EVP_CIPHER_CTX_ctrl(ctx.ctx, C.int(code), C.int(arg), nil)
	if res != 1 {
		return fmt.Errorf("failed to set code %d to %d [result %d]",
			code, arg, res)
	}
	return nil
}

func (ctx *cipherCtx) setCtrlBytes(code, arg int, value []byte) error {
	res := C.EVP_CIPHER_CTX_ctrl(ctx.ctx, C.int(code), C.int(arg),
		unsafe.Pointer(&value[0]))
	if res != 1 {
		return fmt.Errorf("failed to set code %d with arg %d to %x [result %d]",
			code, arg, value, res)
	}
	return nil
}

func (ctx *cipherCtx) getCtrlInt(code, arg int) (int, error) {
	var returnVal C.int
	res := C.EVP_CIPHER_CTX_ctrl(ctx.ctx, C.int(code), C.int(arg),
		unsafe.Pointer(&returnVal))
	if res != 1 {
		return 0, fmt.Errorf("failed to get code %d with arg %d [result %d]",
			code, arg, res)
	}
	return int(returnVal), nil
}

func (ctx *cipherCtx) getCtrlBytes(code, arg, expectsize int) ([]byte, error) {
	returnVal := make([]byte, expectsize)
	res := C.EVP_CIPHER_CTX_ctrl(ctx.ctx, C.int(code), C.int(arg),
		unsafe.Pointer(&returnVal[0]))
	if res != 1 {
		return nil, fmt.Errorf("failed to get code %d with arg %d [result %d]",
			code, arg, res)
	}
	return returnVal, nil
}

func (ctx *encryptionCipherCtx) EncryptUpdate(input []byte) ([]byte, error) {
	outbuf := make([]byte, len(input)+ctx.BlockSize())
	outlen := C.int(len(outbuf))
	res := C.EVP_EncryptUpdate(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&input[0]), C.int(len(input)))
	if res != 1 {
		return nil, fmt.Errorf("failed to encrypt [result %d]", res)
	}
	return outbuf[:outlen], nil
}

func (ctx *decryptionCipherCtx) DecryptUpdate(input []byte) ([]byte, error) {
	outbuf := make([]byte, len(input)+ctx.BlockSize())
	outlen := C.int(len(outbuf))
	res := C.EVP_DecryptUpdate(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&input[0]), C.int(len(input)))
	if res != 1 {
		return nil, fmt.Errorf("failed to decrypt [result %d]", res)
	}
	return outbuf[:outlen], nil
}

func (ctx *encryptionCipherCtx) EncryptFinal() ([]byte, error) {
	outbuf := make([]byte, ctx.BlockSize())
	var outlen C.int
	if 1 != C.EVP_EncryptFinal_ex(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, errors.New("encryption failed")
	}
	return outbuf[:outlen], nil
}

func (ctx *decryptionCipherCtx) DecryptFinal() ([]byte, error) {
	outbuf := make([]byte, ctx.BlockSize())
	var outlen C.int
	if 1 != C.EVP_DecryptFinal_ex(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen) {
		// this may mean the tag failed to verify- all previous plaintext
		// returned must be considered faked and invalid
		return nil, errors.New("decryption failed")
	}
	return outbuf[:outlen], nil
}

type authEncryptionCipherCtx struct {
	encryptionCipherCtx
}

type authDecryptionCipherCtx struct {
	decryptionCipherCtx
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
	return &authEncryptionCipherCtx{*ctx}, nil
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
	return &authDecryptionCipherCtx{*ctx}, nil
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
