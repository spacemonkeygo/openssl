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
	"errors"
)

type TLSTicket struct {
	name []byte
	aes  []byte
	hmac []byte
}

type TLSTicketStatus int

const (
	TLSTicketError 	TLSTicketStatus = 0
	TLSTicketResume	TLSTicketStatus = 1
	TLSTicketRenew	TLSTicketStatus = 2
)

// NewTLSTicket creates a TLS Ticket rfc5077.
// See http://www.ietf.org/rfc/rfc5077 for more.
func NewTLSTicket(ticketBlock []byte) (*TLSTicket, error) {
	if len(ticketBlock) != 48 {
		return nil, errors.New("TLS ticket file's length is not 48 bytes")
	}

	return &TLSTicket{name: ticketBlock[:16], aes: ticketBlock[16:32], 
		hmac: ticketBlock[32:48]}, nil
}

// TLS Ticket callback function.
// See TLSTicketStatus for more details and 
// https://www.openssl.org/docs/ssl/SSL_CTX_set_tlsext_ticket_key_cb.html.
type TLSTicketCallback func(status TLSTicketStatus)
