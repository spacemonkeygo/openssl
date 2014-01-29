// Copyright (C) 2014 Space Monkey, Inc.

package openssl

import (
    "bytes"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "encoding/hex"
    "io/ioutil"
    "testing"
)

func TestMarshal(t *testing.T) {
    key, err := LoadPrivateKey(keyBytes)
    if err != nil {
        t.Fatal(err)
    }
    cert, err := LoadCertificate(certBytes)
    if err != nil {
        t.Fatal(err)
    }

    pem, err := cert.MarshalPEM()
    if err != nil {
        t.Fatal(err)
    }
    if !bytes.Equal(pem, certBytes) {
        ioutil.WriteFile("generated", pem, 0644)
        ioutil.WriteFile("hardcoded", certBytes, 0644)
        t.Fatal("invalid cert pem bytes")
    }

    pem, err = key.MarshalPKCS1PrivateKeyPEM()
    if err != nil {
        t.Fatal(err)
    }
    if !bytes.Equal(pem, keyBytes) {
        ioutil.WriteFile("generated", pem, 0644)
        ioutil.WriteFile("hardcoded", keyBytes, 0644)
        t.Fatal("invalid private key pem bytes")
    }
    tls_cert, err := tls.X509KeyPair(certBytes, keyBytes)
    if err != nil {
        t.Fatal(err)
    }
    tls_key, ok := tls_cert.PrivateKey.(*rsa.PrivateKey)
    if !ok {
        t.Fatal("FASDFASDF")
    }
    _ = tls_key

    der, err := key.MarshalPKCS1PrivateKeyDER()
    if err != nil {
        t.Fatal(err)
    }
    tls_der := x509.MarshalPKCS1PrivateKey(tls_key)
    if !bytes.Equal(der, tls_der) {
        t.Fatal("invalid private key der bytes: %s\n v.s. %s\n", hex.Dump(der), hex.Dump(tls_der))
    }

    der, err = key.MarshalPKIXPublicKeyDER()
    if err != nil {
        t.Fatal(err)
    }
    tls_der, err = x509.MarshalPKIXPublicKey(&tls_key.PublicKey)
    if err != nil {
        t.Fatal(err)
    }
    if !bytes.Equal(der, tls_der) {
        ioutil.WriteFile("generated", []byte(hex.Dump(der)), 0644)
        ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
        t.Fatal("invalid public key der bytes")
    }
}
