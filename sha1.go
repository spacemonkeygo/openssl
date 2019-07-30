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

// #include "shim.h"
import "C"

type SHA1Hash struct {
	*DigestComputer
}

func NewSHA1Hash() (*SHA1Hash, error) { return NewSHA1HashWithEngine(nil) }

func NewSHA1HashWithEngine(e *Engine) (*SHA1Hash, error) {
	dc, err := NewDigestComputerWithEngine(e, EVP_SHA1)
	if err != nil {
		return nil, err
	}
	return &SHA1Hash{DigestComputer: dc}, nil
}

func (s *SHA1Hash) Sum() (result [20]byte, err error) {
	sum, err := s.DigestComputer.Sum()
	if err != nil {
		return
	}
	copy(result[:], sum)
	return
}

func SHA1(data []byte) (result [20]byte, err error) {
	hash, err := NewSHA1Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	return hash.Sum()
}
