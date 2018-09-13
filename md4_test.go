// Copyright (C) 2017. See AUTHORS.
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

package openssl

import (
	"crypto/rand"
	"golang.org/x/crypto/md4"
	"io"
	"testing"
)

func TestMD4(t *testing.T) {
	for i := 0; i < 100; i++ {
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}

		expected := [16]byte{}
		md4Ctx := md4.New()
		md4Ctx.Write(buf)
		copy(expected[:], md4Ctx.Sum(nil))
		got, err := MD4(buf)
		if err != nil {
			t.Fatal(err)
		}

		if expected != got {
			t.Fatalf("exp:%x got:%x", expected, got)
		}
	}
}

func TestMD4Writer(t *testing.T) {
	ohash, err := NewMD4Hash()
	if err != nil {
		t.Fatal(err)
	}
	hash := md4.New()

	for i := 0; i < 100; i++ {
		if err := ohash.Reset(); err != nil {
			t.Fatal(err)
		}
		hash.Reset()
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}

		if _, err := ohash.Write(buf); err != nil {
			t.Fatal(err)
		}
		if _, err := hash.Write(buf); err != nil {
			t.Fatal(err)
		}

		var got, exp [16]byte

		hash.Sum(exp[:0])
		got, err := ohash.Sum()
		if err != nil {
			t.Fatal(err)
		}

		if got != exp {
			t.Fatalf("exp:%x got:%x", exp, got)
		}
	}
}

type md4func func([]byte)

func benchmarkMD4(b *testing.B, length int64, fn md4func) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(length)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(buf)
	}
}

func BenchmarkMD4Large_openssl(b *testing.B) {
	benchmarkMD4(b, 1024*1024, func(buf []byte) { MD4(buf) })
}

func BenchmarkMD4Large_stdlib(b *testing.B) {
	benchmarkMD4(b, 1024*1024, func(buf []byte) {
		md4Ctx := md4.New()
		md4Ctx.Write(buf)
		md4Ctx.Sum(nil)
	})
}

func BenchmarkMD4Small_openssl(b *testing.B) {
	benchmarkMD4(b, 1, func(buf []byte) { MD4(buf) })
}

func BenchmarkMD4Small_stdlib(b *testing.B) {
	benchmarkMD4(b, 1, func(buf []byte) {
		md4Ctx := md4.New()
		md4Ctx.Write(buf)
		md4Ctx.Sum(nil)
	})
}
