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
	"bytes"
	"io"
	"sync"
	"testing"
	"unsafe"
)

var gFoundServerName bool = false
var gServerName string
var gCallbackData string = "some callback data"

func passThroughServername() func(ssl Conn, ad int, arg unsafe.Pointer) int {
	x := func(ssl Conn, ad int, arg unsafe.Pointer) int {
		cbData := (*string)(arg)
		if *cbData != gCallbackData { //we should getthe callback data we set on the CTX
			return 1
		}
		name := ssl.GetServerName()
		if name == gServerName {
			gFoundServerName = true
			//here we'd normally do soemthing like get a CTX for the specific server name and
			//set it on the conn.
		} else {
			gFoundServerName = false
		}
		return 0
	}
	return x
}

func TestTLSExtSNI(t *testing.T) {
	//setup SNI On the CTX
	server_conn, client_conn := NetPipe(t)
	defer server_conn.Close()
	defer client_conn.Close()

	server, client := OpenSSLConstructor(t, server_conn, client_conn)
	cconn := client.(*Conn)
	sconn := server.(*Conn)
	ctx := (*sconn).ctx
	//setup SNI On the CTX
	rc := ctx.SetTlsExtServerNameCallback(passThroughServername(), unsafe.Pointer(&gCallbackData))
	if rc != 0 {
		t.Fatal("Expected 0 from ctx.SetTlsExtServerNameCallback, but got %d", rc)
	}
	data := "first test string\n"
	host := "test-host"

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		gServerName = host
		err := cconn.SetTlsExtHostName(host)
		if err != nil {
			t.Fatal(err)
		}

		err = client.Handshake()
		if err != nil {
			t.Fatal(err)
		}

		_, err = io.Copy(client, bytes.NewReader([]byte(data)))
		if err != nil {
			t.Fatal(err)
		}

		err = client.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()
	go func() {
		defer wg.Done()

		err := server.Handshake()
		if err != nil {
			t.Fatal(err)
		}

		buf := bytes.NewBuffer(make([]byte, 0, len(data)))
		_, err = io.CopyN(buf, server, int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		if string(buf.Bytes()) != data {
			t.Fatal("mismatched data")
		}

		err = server.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()
	wg.Wait()
	if gFoundServerName == false {
		t.Fatal("Expected gFoundServerName to be set to true")
	}
	if gServerName != host {
		t.Fatal("Expected gServerName to be '%s', but it was '%s'", host, gServerName)
	}
}
