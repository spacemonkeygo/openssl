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

type MD4Hash struct {
	*DigestComputer
}

func NewMD4Hash() (*MD4Hash, error) { return NewMD4HashWithEngine(nil) }

func NewMD4HashWithEngine(e *Engine) (*MD4Hash, error) {
	dc, err := NewDigestComputerWithEngine(e, EVP_MD4)
	if err != nil {
		return nil, err
	}
	return &MD4Hash{DigestComputer: dc}, nil
}

func (s *MD4Hash) Sum() (result [16]byte, err error) {
	sum, err := s.DigestComputer.Sum()
	if err != nil {
		return
	}
	copy(result[:], sum)
	return
}

func MD4(data []byte) (result [16]byte, err error) {
	hash, err := NewMD4Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	return hash.Sum()
}
