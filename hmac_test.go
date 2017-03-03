// Copyright (C) 2014 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build cgo

package openssl

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSHA256HMAC(t *testing.T) {
	key := []byte("d741787cc61851af045ccd37")
	data := []byte("5912EEFD-59EC-43E3-ADB8-D5325AEC3271")
	h, _ := NewHMAC(key, EVP_SHA256)
	h.Write(data)

	var err error
	var actualHMACBytes []byte
	if actualHMACBytes, err = h.Final(); err != nil {
		t.Fatalf("Error while finalizing HMAC: %s", err)
	}
	actualString := hex.EncodeToString(actualHMACBytes)

	// generate HMAC with built-in crypto lib
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expectedString := hex.EncodeToString(mac.Sum(nil))

	if expectedString != actualString {
		t.Errorf("HMAC was incorrect: expected=%s, actual=%s", expectedString, actualString)
	}
}

func BenchmarkSHA256HMAC(b *testing.B) {
	h, _ := NewHMAC([]byte("d741787cc61851af045ccd37"), EVP_SHA256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write([]byte("5912EEFD-59EC-43E3-ADB8-D5325AEC3271"))

		var err error
		if _, err = h.Final(); err != nil {
			b.Fatalf("Error while finalizing HMAC: %s", err)
		}
	}
}
