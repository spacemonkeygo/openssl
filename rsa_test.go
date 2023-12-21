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
	"encoding/hex"
	"testing"
)

func Test_Unit_ParseRSAPublicKeyPKCS1(t *testing.T) {
	rsaPubKeyHex := "30819f300d06092a864886f70d010101050003818d0030818902818100c66ee1df2b07469ec8a45d2307500cdd30fddf514356062a6e651ccdd667f050c462cca3932a7a1e28b59b20071a7897736b12fac21bbc5a66cc64e74adf222cef3dda627512efdbc89bf9a0d77dfcc33417110aaf218dbcb7090b95395535a557c0a621ab7dbdc764061fb3644141f363cd2bd82ce541a9e0a8f22b3e3581d70203010001"
	rsaPubKeyDer, err := hex.DecodeString(rsaPubKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	sut, err := ParseRSAPublicKeyPKCS1(rsaPubKeyDer)
	if err != nil {
		t.Fatal(err)
	}
	if sut.E != 65537 {
		t.Fatal()
	}
	actualN := hex.EncodeToString(sut.N.Bytes())
	if actualN != "c66ee1df2b07469ec8a45d2307500cdd30fddf514356062a6e651ccdd667f050c462cca3932a7a1e28b59b20071a7897736b12fac21bbc5a66cc64e74adf222cef3dda627512efdbc89bf9a0d77dfcc33417110aaf218dbcb7090b95395535a557c0a621ab7dbdc764061fb3644141f363cd2bd82ce541a9e0a8f22b3e3581d7" {
		t.Fatal(actualN)
	}
}
