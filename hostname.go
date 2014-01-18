// Copyright (C) 2014 Space Monkey, Inc.

package openssl

/*
#cgo pkg-config: openssl
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/x509.h>

#ifndef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
#define X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT	0x1
#define X509_CHECK_FLAG_NO_WILDCARDS	0x2

extern int X509_check_host(X509 *x, const unsigned char *chk, size_t chklen,
    unsigned int flags);
extern int X509_check_email(X509 *x, const unsigned char *chk, size_t chklen,
    unsigned int flags);
extern int X509_check_ip(X509 *x, const unsigned char *chk, size_t chklen,
		unsigned int flags);
#endif
*/
import "C"

import (
    "net"
    "unsafe"

    "code.spacemonkey.com/go/errors"
)

var (
    ValidationError = errors.New(SSLError, "Host validation error")
)

type CheckFlags int

const (
    AlwaysCheckSubject CheckFlags = C.X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
    NoWildcards        CheckFlags = C.X509_CHECK_FLAG_NO_WILDCARDS
)

func (c *Certificate) CheckHost(host string, flags CheckFlags) error {
    chost := unsafe.Pointer(C.CString(host))
    defer C.free(chost)
    rv := C.X509_check_host(c.x, (*C.uchar)(chost), C.size_t(len(host)),
        C.uint(flags))
    if rv > 0 {
        return nil
    }
    if rv == 0 {
        return ValidationError.New(
            "cert failed validation for host %s", host)
    }
    return SSLError.New("hostname validation failed")
}

func (c *Certificate) CheckEmail(email string, flags CheckFlags) error {
    cemail := unsafe.Pointer(C.CString(email))
    defer C.free(cemail)
    rv := C.X509_check_email(c.x, (*C.uchar)(cemail), C.size_t(len(email)),
        C.uint(flags))
    if rv > 0 {
        return nil
    }
    if rv == 0 {
        return ValidationError.New(
            "cert failed validation for email %s", email)
    }
    return SSLError.New("email validation failed")
}

func (c *Certificate) CheckIP(ip net.IP, flags CheckFlags) error {
    cip := unsafe.Pointer(&ip[0])
    rv := C.X509_check_ip(c.x, (*C.uchar)(cip), C.size_t(len(ip)),
        C.uint(flags))
    if rv > 0 {
        return nil
    }
    if rv == 0 {
        return ValidationError.New(
            "cert failed validation for ip %s", ip.String())
    }
    return SSLError.New("ip validation failed")
}

func (c *Certificate) VerifyHostname(host string) error {
    var ip net.IP
    if len(host) >= 3 && host[0] == '[' && host[len(host)-1] == ']' {
        ip = net.ParseIP(host[1 : len(host)-1])
    } else {
        ip = net.ParseIP(host)
    }
    if ip != nil {
        return c.CheckIP(ip, 0)
    }
    return c.CheckHost(host, 0)
}
