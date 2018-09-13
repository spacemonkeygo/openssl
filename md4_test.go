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
	"encoding/hex"
	"io"
	"testing"
)

var md4Examples = []struct{ out, in string }{
	{"31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"93875419eca14bbf961e412147839d04", "99"},
	{"89b4c9a073ae963f95370a9a1e897a74", "7b89"},
	{"be47aa5b399de162db079674047af65b", "803c78"},
	{"6d97329845e30e79335fef1eb9d76d5e", "79b08de9"},
	{"7115059e7a77e50cf722afbaad19611d", "42251df47b"},
	{"468d3dfe53a140993d10cb977708c22c", "bd0ae6faa6e8"},
	{"97f951156d4fe99e935b437ea5535a85", "ce511e2fd6e596"},
	{"e50e5be10795a54d45aba39e6af2ecd5", "3f526ded71688ef0"},
	{"c6c6d4ba2070c842f4d4388e3919a75c", "68aa2699f3fd154a5c"},
	{"821fac95ab8a7443e3e0a47711e3e4ae", "133fc4081c3c9d0fe962"},
	{"ac9e63ee02c6fdc097de1e2735cd1415", "f2b43f4e0e4448054e57fc"},
	{"db82e7f6c26468e41b9f34082dcbf976", "ba8d2fd4323e389a23477216"},
	{"bdd168bbe205e36bb852518113247a9e", "3b3b832ff6ff259ab028689bc5"},
	{"c08b6b2eeab0bf3234314eb6a573cd9e", "ef0746f1fba74e018d718e74bdf1"},
	{"0c2b7a7701bbe40f4668677cf3cc9bb9", "d3fd98ccbf59e8f61277ec9a668212"},
	{"ce5087675d227d65de1ae02db2c8aec4", "551705b22d1b12c7056018d8a8468a7b"},
	{"8130c37467524e6ab64999c4bde575a4", "d075bb0ee09f90399508e27d3059619abf"},
	{"736cea235c6e67772a05d5c4c24ed5bb", "53a1880520136e99a5e42235a706ca929c5c"},
	{"cdd0dc65d134efe608113ad57c053e82", "b15c56e59f525c60d563a0064866b2a8550aa8"},
	{"29105f10e7570f7242e0b8f3a3514f82", "f4e6b432479abb4095cd7e4788ce9cf077acc932"},
	{"33f1a70b35b51f42704aec6a01d06f8f", "6b0e95b9a09996809a1ac25142be3d46a01b78c26d"},
	{"bf4a3ebf686409832d92ac0ecf70fc6e", "ee0f76cd3e233058ba311fefc089ce1d9217ab3ae229"},
	{"5359d01e422ce2617f516e48b1693003", "57788a4e5514fbec6a7db6abf3f8d41cba2c843496467b"},
	{"a8ad7335fa62b8f4eb40f711b2793972", "840ca6f027703fe7119bba138bfc399d8c9725854b7a36c1"},
	{"5bf38c84aa17043ca1ac3b6a0d70d6f6", "a8340d43b3c2f19b963f16989b60aab83a5e90415f205fdd99"},
	{"612e96a3a484716f8648874b1b3e8b16", "e66e7141838666e06e01d45dc9eaab610bf46710287b9ad6b40e"},
	{"d436e950d55f25548c86ebf065a5d23e", "e8af98c8e8d86f7df0d65e225c0d48c075fafc27733d28b4a53077"},
	{"b48d7af2252ec0107f5631736d756ff9", "34554eb3f2df01135aab9a157c0de8c5804c9df20b8241b83b7999e1"},
	{"bcd8447e2c1de19c076c8b7a04f7469e", "af7ecf59b66eea345800d48e00e2953eb654efbf433abb27ad2c497a08"},
	{"1eeb6f74cf827b50d285d6749404c5e3", "c0f89522341128dc5e5e73c8b96775d7eb3d550d9786cc88b23479e14d11"},
	{"6e593341e62194911d5cc31e39835f27", "c5e4bc73821faa34adf9468441ffd97520a96cd5debda4d51edcaaf2b23fbd"},
}

func TestMD4Examples(t *testing.T) {
	for _, ex := range md4Examples {
		buf, err := hex.DecodeString(ex.in)
		if err != nil {
			t.Fatal(err)
		}

		got, err := MD4(buf)
		if err != nil {
			t.Fatal(err)
		}

		if hgot := hex.EncodeToString(got[:]); hgot != ex.out {
			t.Fatalf("%s: %s != %s", ex.in, hgot, ex.out)
		}
	}
}

func TestMD4Writer(t *testing.T) {
	ohash, err := NewMD4Hash()
	if err != nil {
		t.Fatal(err)
	}

	for _, ex := range md4Examples {
		if err := ohash.Reset(); err != nil {
			t.Fatal(err)
		}

		buf, err := hex.DecodeString(ex.in)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ohash.Write(buf); err != nil {
			t.Fatal(err)
		}

		got, err := ohash.Sum()
		if err != nil {
			t.Fatal(err)
		}

		if hgot := hex.EncodeToString(got[:]); hgot != ex.out {
			t.Fatalf("%s: %s != %s", ex.in, hgot, ex.out)
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

func BenchmarkMD4Small_openssl(b *testing.B) {
	benchmarkMD4(b, 1, func(buf []byte) { MD4(buf) })
}
