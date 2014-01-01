// Copyright (C) 2014 Space Monkey, Inc.

package openssl

import (
    "net"
)

type listener struct {
    net.Listener
    ctx *Ctx
}

func (l *listener) Accept() (c net.Conn, err error) {
    c, err = l.Listener.Accept()
    if err != nil {
        return nil, err
    }
    return Server(c, l.ctx)
}

func NewListener(inner net.Listener, ctx *Ctx) net.Listener {
    return &listener{
        Listener: inner,
        ctx:      ctx}
}
