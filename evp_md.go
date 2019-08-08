package openssl

// #include "openssl/opensslv.h"
// #include "shim.h"
import "C"

// EVP_MD represents hash function implemented by OpenSSL
type EVP_MD int

const (
	EVP_NULL      EVP_MD = iota
	EVP_MD5
	EVP_MD4
	EVP_SHA
	EVP_SHA1
	EVP_DSS
	EVP_DSS1
	EVP_MDC2
	EVP_RIPEMD160
	EVP_SHA224
	EVP_SHA256
	EVP_SHA384
	EVP_SHA512
	EVP_SHA512_224
	EVP_SHA512_256
	EVP_BLAKE2B_512
	EVP_BLAKE2S_256
	EVP_GOST
	EVP_MD2
	EVP_SHA3_224
	EVP_SHA3_256
	EVP_SHA3_384
	EVP_SHA3_512
	EVP_SHAKE128
	EVP_SHAKE256
	EVP_SM3
	EVP_WHIRLPOOL
)

// Size returns the size of the digest
func (evp EVP_MD) Size() int {
	var bits int
	switch evp {
	case EVP_BLAKE2B_512:
		bits = 512
	case EVP_BLAKE2S_256:
		bits = 256
	case EVP_GOST:
		bits = 256
	case EVP_MD2:
		bits = 128
	case EVP_MD4:
		bits = 128
	case EVP_MD5:
		bits = 128
	case EVP_RIPEMD160:
		bits = 160
	case EVP_SHA1:
		bits = 160
	case EVP_SHA224:
		bits = 224
	case EVP_SHA256:
		bits = 256
	case EVP_SHA384:
		bits = 384
	case EVP_SHA512:
		bits = 512
	case EVP_SHA512_224:
		bits = 224
	case EVP_SHA512_256:
		bits = 256
	case EVP_SHA3_224:
		bits = 224
	case EVP_SHA3_256:
		bits = 256
	case EVP_SHA3_384:
		bits = 384
	case EVP_SHA3_512:
		bits = 512
	case EVP_SHAKE128:
		bits = 128
	case EVP_SHAKE256:
		bits = 256
	case EVP_SM3:
		bits = 256
	}
	return bits / 8
}

// Size returns hash function block size in bytes
func (evp EVP_MD) BlockSize() int {
	var bits int
	switch evp {
	case EVP_BLAKE2B_512:
		bits = 1024
	case EVP_BLAKE2S_256:
		bits = 512
	case EVP_GOST:
		bits = 256
	case EVP_MD2:
		bits = 128
	case EVP_MD4:
		bits = 512
	case EVP_MD5:
		bits = 512
	case EVP_RIPEMD160:
		bits = 512
	case EVP_SHA1:
		bits = 512
	case EVP_SHA224:
		bits = 512
	case EVP_SHA256:
		bits = 512
	case EVP_SHA384:
		bits = 1024
	case EVP_SHA512:
		bits = 1024
	case EVP_SHA512_224:
		bits = 1024
	case EVP_SHA512_256:
		bits = 1024
	case EVP_SHA3_224:
		bits = 1124
	case EVP_SHA3_256:
		bits = 1088
	case EVP_SHA3_384:
		bits = 832
	case EVP_SHA3_512:
		bits = 576
	case EVP_SHAKE128:
		bits = 1344
	case EVP_SHAKE256:
		bits = 1088
	case EVP_SM3:
		bits = 512
	}
	return bits / 8
}

func (evp EVP_MD) String() string {
	switch evp {
	case EVP_BLAKE2B_512:
		return "BLAKE2B_512"
	case EVP_BLAKE2S_256:
		return "BLAKE2S_256"
	case EVP_GOST:
		return "GOST"
	case EVP_MD2:
		return "MD2"
	case EVP_MD4:
		return "MD4"
	case EVP_MD5:
		return "MD5"
	case EVP_RIPEMD160:
		return "RMD160"
	case EVP_SHA1:
		return "SHA1"
	case EVP_SHA224:
		return "SHA224"
	case EVP_SHA256:
		return "SHA256"
	case EVP_SHA384:
		return "SHA384"
	case EVP_SHA512:
		return "SHA512"
	case EVP_SHA512_224:
		return "SHA512_224"
	case EVP_SHA512_256:
		return "SHA512_256"
	case EVP_SHA3_224:
		return "SHA3_224"
	case EVP_SHA3_256:
		return "SHA3_256"
	case EVP_SHA3_384:
		return "SHA3_384"
	case EVP_SHA3_512:
		return "SHA3_512"
	case EVP_SHAKE128:
		return "SHAKE128"
	case EVP_SHAKE256:
		return "SHAKE256"
	case EVP_SM3:
		return "SM3"
	default:
		return "UNKNOWN"
	}
}


/*
OpenSSL compatibility table:

1.1.1 -> 0x1010100fL
1.1.0 -> 0x1010000fL

Digest	    1.0.2	1.1.0	1.1.1
BLAKE2B512	-	    +	    +
BLAKE2S256	-	    +	    +
GOST	    -	    +	    +
MD2	        -	    +	    +
MD4	        +	    +	    +
MD5	        +	    +	    +
RIPEMD160	+	    +	    +
SHA1	    +	    +	    +
SHA224	    +	    +	    +
SHA256	    +	    +	    +
SHA384	    +	    +	    +
SHA512	    +	    +	    +
SHA512-224	-	    -	    +
SHA512-256	-	    -	    +
SHA3-224	-	    -	    +
SHA3-256	-	    -	    +
SHA3-384	-	    -	    +
SHA3-512	-	    -	    +
SHAKE128	-	    -	    +
SHAKE256	-	    -	    +
SM3	        -	    -	    +
WHIRLPOOL	+	    +	    +
*/

var hashFunctionsOpenSSLv111 = map[EVP_MD]bool{
	EVP_BLAKE2B_512: true,
	EVP_BLAKE2S_256: true,
	EVP_GOST: true,
	EVP_MD2: true,
	EVP_MD4: true,
	EVP_MD5: true,
	EVP_RIPEMD160: true,
	EVP_SHA1: true,
	EVP_SHA224: true,
	EVP_SHA256: true,
	EVP_SHA384: true,
	EVP_SHA512: true,
	EVP_SHA512_224: true,
	EVP_SHA512_256: true,
	EVP_SHA3_224: true,
	EVP_SHA3_256: true,
	EVP_SHA3_384: true,
	EVP_SHA3_512: true,
	EVP_SHAKE128: true,
	EVP_SHAKE256: true,
	EVP_SM3: true,
	EVP_WHIRLPOOL: true,
}

var hashFunctionsOpenSSLv110 = map[EVP_MD]bool{
	EVP_BLAKE2B_512: true,
	EVP_BLAKE2S_256: true,
	EVP_GOST: true,
	EVP_MD2: true,
	EVP_MD4: true,
	EVP_MD5: true,
	EVP_RIPEMD160: true,
	EVP_SHA1: true,
	EVP_SHA224: true,
	EVP_SHA256: true,
	EVP_SHA384: true,
	EVP_SHA512: true,
	EVP_SHA512_224: false,
	EVP_SHA512_256: false,
	EVP_SHA3_224: false,
	EVP_SHA3_256: false,
	EVP_SHA3_384: false,
	EVP_SHA3_512: false,
	EVP_SHAKE128: false,
	EVP_SHAKE256: false,
	EVP_SM3: false,
	EVP_WHIRLPOOL: true,
}

var hashFunctionsOpenSSLv102 = map[EVP_MD]bool{
	EVP_BLAKE2B_512: false,
	EVP_BLAKE2S_256: false,
	EVP_GOST: false,
	EVP_MD2: false,
	EVP_MD4: true,
	EVP_MD5: true,
	EVP_RIPEMD160: true,
	EVP_SHA1: true,
	EVP_SHA224: true,
	EVP_SHA256: true,
	EVP_SHA384: true,
	EVP_SHA512: true,
	EVP_SHA512_224: false,
	EVP_SHA512_256: false,
	EVP_SHA3_224: false,
	EVP_SHA3_256: false,
	EVP_SHA3_384: false,
	EVP_SHA3_512: false,
	EVP_SHAKE128: false,
	EVP_SHAKE256: false,
	EVP_SM3: false,
	EVP_WHIRLPOOL: true,
}

// Supported checks if this hash function is supported by the installed version of OpenSSL
func (evp EVP_MD) Supported() bool {
	if C.OPENSSL_VERSION_NUMBER >= 0x1010100f {
		return hashFunctionsOpenSSLv111[evp]
	} else if C.OPENSSL_VERSION_NUMBER >= 0x1010000f {
		return hashFunctionsOpenSSLv110[evp]
	}
	return hashFunctionsOpenSSLv102[evp]
}

// c returns pointer to the struct that is used during digest initialization
func (evp EVP_MD) c() (evpMD *C.EVP_MD) {
	switch evp {
	case EVP_BLAKE2B_512:
		evpMD = C.X_EVP_blake2b512()
	case EVP_BLAKE2S_256:
		evpMD = C.X_EVP_blake2s256()
	case EVP_GOST:
		panic("Not implemented yet")
	case EVP_MD2:
		evpMD = C.X_EVP_md2()
	case EVP_MD4:
		evpMD = C.X_EVP_md4()
	case EVP_MD5:
		evpMD = C.X_EVP_md5()
	case EVP_RIPEMD160:
		evpMD = C.X_EVP_ripemd160()
	case EVP_SHA1:
		evpMD = C.X_EVP_sha1()
	case EVP_SHA224:
		evpMD = C.X_EVP_sha224()
	case EVP_SHA256:
		evpMD = C.X_EVP_sha256()
	case EVP_SHA384:
		evpMD = C.X_EVP_sha384()
	case EVP_SHA512:
		evpMD = C.X_EVP_sha512()
	case EVP_SHA512_224:
		evpMD = C.X_EVP_sha512_224()
	case EVP_SHA512_256:
		evpMD = C.X_EVP_sha512_256()
	case EVP_SHA3_224:
		evpMD = C.X_EVP_sha3_224()
	case EVP_SHA3_256:
		evpMD = C.X_EVP_sha3_256()
	case EVP_SHA3_384:
		evpMD = C.X_EVP_sha3_384()
	case EVP_SHA3_512:
		evpMD = C.X_EVP_sha3_512()
	case EVP_SHAKE128:
		evpMD = C.X_EVP_shake128()
	case EVP_SHAKE256:
		evpMD = C.X_EVP_shake256()
	case EVP_SM3:
		panic("Not implemented yet")
	default:
		panic("Not implemented yet")
	}
	return
}

