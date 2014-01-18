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

func Listen(network, laddr string, ctx *Ctx) (net.Listener, error) {
    if ctx == nil {
        return nil, SSLError.New("no ssl context provided")
    }
    l, err := net.Listen(network, laddr)
    if err != nil {
        return nil, err
    }
    return NewListener(l, ctx), nil
}

type DialFlags int

const (
    InsecureSkipHostVerification DialFlags = 0
)

func Dial(network, addr string, ctx *Ctx, flags DialFlags) (*Conn, error) {
    if ctx == nil {
        var err error
        ctx, err = NewCtx()
        if err != nil {
            return nil, err
        }
        // TODO: use operating system default certificate chain?
    }
    c, err := net.Dial(network, addr)
    if err != nil {
        return nil, err
    }
    conn, err := Client(c, ctx)
    if err != nil {
        c.Close()
        return nil, err
    }
    err = conn.Handshake()
    if err != nil {
        c.Close()
        return nil, err
    }
    if flags&InsecureSkipHostVerification == 0 {
        err = conn.VerifyHostname(addr)
        if err != nil {
            conn.Close()
            return nil, err
        }
    }
    return conn, nil
}
