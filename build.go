package openssl

// #cgo !windows pkg-config: openssl
// #cgo windows CFLAGS: -I /c/work/vendor/include -DWIN32_LEAN_AND_MEAN
// #cgo windows LDFLAGS: -L /c/work/vendor/libs -lssl -lcrypto
import "C"
