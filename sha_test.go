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

package openssl

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

type shaTest struct {
	out string
	in  string
}

var golden = []shaTest{
	{"f96cea198ad1dd5617ac084a3d92c6107708c0ef", ""},
	{"37f297772fae4cb1ba39b6cf9cf0381180bd62f2", "a"},
	{"488373d362684af3d3f7a6a408b59dfe85419e09", "ab"},
	{"0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", "abc"},
	{"082c73b06f71185d840fb4b28eb3abade67714bc", "abcd"},
	{"d624e34951bb800f0acae773001df8cffe781ba8", "abcde"},
	{"2a589f7750598dc0ea0a608719e04327f609279a", "abcdef"},
	{"5bdf01f9298e9d19d3f8d15520fd74eed600b497", "abcdefg"},
	{"734ba8b31975d0dbae4d6e249f4e8da270796c94", "abcdefgh"},
	{"e85c35055b093f7b9948898d2e7fbaf13b7ed3b4", "abcdefghi"},
	{"ac2f1f843ebb6805940ae2da76b62d11ce0c2dfb", "abcdefghij"},
	{"43f87ce8207df8464ec94df98c6de614259f9f9b", "Discard medicine more than two years old."},
	{"556a4b84a7aae18d533c490cc6166bceeadb1e78", "He who has a shady past knows that nice guys finish last."},
	{"154c149aebd6c69113a831b410d677aef75d8c16", "I wouldn't marry him with a ten foot pole."},
	{"030c1ac6c94babda05f15127ef25455a090de6d8", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
	{"66f72cd3e3102a22d9921f92e1080816cc6829a6", "The days of the digital watch are numbered.  -Tom Stoppard"},
	{"519d3b4cbaba8d214d955bcc1b6af0f9f8d4a73a", "Nepal premier won't resign."},
	{"a633be186221a0a6715e0cb7f170c2be6a595434", "For every action there is an equal and opposite government program."},
	{"0255fc603ab48b6f9df88990f78262359e641621", "His money is twice tainted: 'taint yours and 'taint mine."},
	{"693919e639922d0b8242115512ec5cc904758fbc", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
	{"17e56ae76e612337ad7b634aa839271d60beda96", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
	{"9d3d0f7017181467bc453dbb83b676ea27291604", "size:  a.out:  bad magic"},
	{"1cc69323cc1a8523a672372c8dc076d6d2f64381", "The major problem is with sendmail.  -Mark Horton"},
	{"acd8d33701fc3e776ca7113e83917f87185f01a0", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"},
	{"8803803ded9426a430761e54addc38e4541f729e", "If the enemy is within range, then so are you."},
	{"e8875d30c04df24335db4a989c5ac5de295a932b", "It's well we cannot hear the screams/That we create in others' dreams."},
	{"6ce8c4a10827943b88f0fc00fb075129236c3100", "You remind me of a TV show, but that's all right: I watch it anyway."},
	{"941a49d51f52c2e55a54de58f49787605e6572aa", "C is as portable as Stonehedge!!"},
	{"34af7a6ff354b6d0bce0a09af0984ccae2a0d14c", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"},
	{"2398df93efff72e5a041c092b13b81844b196c28", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"},
	{"7dda7376c190859ad60e072139fc1028171aab4b", "How can you write a big system without C++?  -Paul Glick"},
}

func TestSHA(t *testing.T) {
	for _, g := range golden {
		got, err := SHA([]byte(g.in))
		if err != nil {
			t.Fatal(err)
		}

		s := fmt.Sprintf("%x", got)
		if s != g.out {
			t.Fatalf("Sum function: sha(%s) = %s want %s", g.in, s, g.out)
		}
	}
}

func benchmarkSHA(b *testing.B, length int64) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(length)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SHA(buf)
	}
}

func BenchmarkSHALarge(b *testing.B) {
	benchmarkSHA(b, 1024*1024)
}

func BenchmarkSHAMedium(b *testing.B) {
	benchmarkSHA(b, 1024)
}

func BenchmarkSHASmall(b *testing.B) {
	benchmarkSHA(b, 1)
}
