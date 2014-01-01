// Copyright (C) 2014 Space Monkey, Inc.

package openssl

// #cgo pkg-config: openssl
// #include <openssl/ssl.h>
// #include <openssl/conf.h>
// #include <openssl/err.h>
import "C"

import (
    "io"
    "net"
    "runtime"
    "sync"
    "time"
    "unsafe"

    "code.spacemonkey.com/go/errors"
    space_sync "code.spacemonkey.com/go/space/sync"
)

var (
    ErrnoError = errors.New(SSLError, "Errno")

    internalConnError = errors.New(SSLError, "Unhandled internal error")
    zeroReturn        = internalConnError.New("zero return")
    wantRead          = internalConnError.New("want read")
    wantWrite         = internalConnError.New("want write")
    tryAgain          = internalConnError.New("try again")
)

type Conn struct {
    conn             net.Conn
    ssl              *C.SSL
    into_ssl         *readBio
    from_ssl         *writeBio
    is_shutdown      bool
    mtx              sync.Mutex
    want_read_future *space_sync.Future
}

func newSSL(ctx *C.SSL_CTX) (*C.SSL, error) {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    ssl := C.SSL_new(ctx)
    if ssl == nil {
        return nil, errorFromErrorQueue()
    }
    return ssl, nil
}

func newConn(conn net.Conn, ctx *Ctx) (*Conn, error) {
    ssl, err := newSSL(ctx.ctx)
    if err != nil {
        return nil, err
    }

    into_ssl := &readBio{}
    from_ssl := &writeBio{}

    into_ssl_cbio := into_ssl.MakeCBIO()
    from_ssl_cbio := from_ssl.MakeCBIO()
    if into_ssl_cbio == nil || from_ssl_cbio == nil {
        // these frees are null safe
        C.BIO_free(into_ssl_cbio)
        C.BIO_free(from_ssl_cbio)
        C.SSL_free(ssl)
        return nil, SSLError.New("failed to allocate memory BIO")
    }

    // the ssl object takes ownership of these objects now
    C.SSL_set_bio(ssl, into_ssl_cbio, from_ssl_cbio)

    c := &Conn{
        conn:     conn,
        ssl:      ssl,
        into_ssl: into_ssl,
        from_ssl: from_ssl}
    runtime.SetFinalizer(c, func(c *Conn) {
        c.into_ssl.Disconnect(into_ssl_cbio)
        c.from_ssl.Disconnect(from_ssl_cbio)
        C.SSL_free(c.ssl)
    })
    return c, nil
}

func Client(conn net.Conn, ctx *Ctx) (*Conn, error) {
    c, err := newConn(conn, ctx)
    if err != nil {
        return nil, err
    }
    C.SSL_set_connect_state(c.ssl)
    return c, nil
}

func Server(conn net.Conn, ctx *Ctx) (*Conn, error) {
    c, err := newConn(conn, ctx)
    if err != nil {
        return nil, err
    }
    C.SSL_set_accept_state(c.ssl)
    return c, nil
}

func (c *Conn) fillInputBuffer() error {
    for {
        n, err := c.into_ssl.ReadFromOnce(c.conn)
        if n == 0 && err == nil {
            continue
        }
        if err == io.EOF {
            c.into_ssl.MarkEOF()
            return c.Close()
        }
        return err
    }
}

func (c *Conn) flushOutputBuffer() error {
    _, err := c.from_ssl.WriteTo(c.conn)
    return err
}

func (c *Conn) getErrorHandler(rv C.int, errno error) func() error {
    errcode := C.SSL_get_error(c.ssl, rv)
    switch errcode {
    case C.SSL_ERROR_ZERO_RETURN:
        return func() error {
            c.Close()
            return io.ErrUnexpectedEOF
        }
    case C.SSL_ERROR_WANT_READ:
        if c.want_read_future != nil {
            want_read_future := c.want_read_future
            return func() error {
                _, err := want_read_future.Get()
                return err
            }
        }
        c.want_read_future = space_sync.NewFuture()
        want_read_future := c.want_read_future
        return func() (err error) {
            defer func() {
                c.mtx.Lock()
                c.want_read_future = nil
                c.mtx.Unlock()
                want_read_future.Set(nil, err)
            }()
            err = c.flushOutputBuffer()
            if err != nil {
                return err
            }
            err = c.fillInputBuffer()
            if err != nil {
                return err
            }
            return tryAgain
        }
    case C.SSL_ERROR_WANT_WRITE:
        return func() error {
            err := c.flushOutputBuffer()
            if err != nil {
                return err
            }
            return tryAgain
        }
    case C.SSL_ERROR_SYSCALL:
        var err error
        if C.ERR_peek_error() == 0 {
            switch rv {
            case 0:
                err = SSLError.New("Unexpected EOF")
            case -1:
                err = ErrnoError.Wrap(errno)
            default:
                err = errorFromErrorQueue()
            }
        } else {
            err = errorFromErrorQueue()
        }
        return func() error { return err }
    default:
        err := errorFromErrorQueue()
        return func() error { return err }
    }
}

func (c *Conn) handleError(errcb func() error) error {
    if errcb != nil {
        return errcb()
    }
    return nil
}

func (c *Conn) handshake() func() error {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    c.mtx.Lock()
    defer c.mtx.Unlock()
    if c.is_shutdown {
        return func() error { return io.ErrUnexpectedEOF }
    }
    rv, errno := C.SSL_do_handshake(c.ssl)
    if rv > 0 {
        return nil
    }
    return c.getErrorHandler(rv, errno)
}

func (c *Conn) Handshake() error {
    err := tryAgain
    for err == tryAgain {
        err = c.handleError(c.handshake())
        if err == nil {
            return c.flushOutputBuffer()
        }
    }
    return err
}

func (c *Conn) PeerCertificate() (*Certificate, error) {
    c.mtx.Lock()
    if c.is_shutdown {
        return nil, SSLError.New("connection closed")
    }
    x := C.SSL_get_peer_certificate(c.ssl)
    c.mtx.Unlock()
    if x == nil {
        return nil, SSLError.New("no peer certificate found")
    }
    cert := &Certificate{x: x}
    runtime.SetFinalizer(cert, func(cert *Certificate) {
        C.X509_free(cert.x)
    })
    return cert, nil
}

func (c *Conn) shutdown() func() error {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    c.mtx.Lock()
    defer c.mtx.Unlock()
    rv, errno := C.SSL_shutdown(c.ssl)
    if rv > 0 {
        return nil
    }
    if rv == 0 {
        // The OpenSSL docs say that in this case, the shutdown is not
        // finished, and we should call SSL_shutdown() a second time, if a
        // bidirectional shutdown is going to be performed. Further, the
        // output of SSL_get_error may be misleading, as an erroneous
        // SSL_ERROR_SYSCALL may be flagged even though no error occurred.
        // So, TODO: revisit bidrectional shutdown, possibly trying again.
        // Note: some broken clients won't engage in bidirectional shutdown
        // without tickling them to close by sending a TCP_FIN packet, or
        // shutting down the write-side of the connection.
        return nil
    } else {
        return c.getErrorHandler(rv, errno)
    }
}

func (c *Conn) shutdownLoop() error {
    err := tryAgain
    shutdown_tries := 0
    for err == tryAgain {
        shutdown_tries = shutdown_tries + 1
        err = c.handleError(c.shutdown())
        if err == nil {
            return c.flushOutputBuffer()
        }
        if err == tryAgain && shutdown_tries >= 2 {
            return SSLError.New("shutdown requested a third time?")
        }
    }
    if err == io.ErrUnexpectedEOF {
        err = nil
    }
    return err
}

func (c *Conn) Close() error {
    c.mtx.Lock()
    if c.is_shutdown {
        c.mtx.Unlock()
        return nil
    }
    c.is_shutdown = true
    c.mtx.Unlock()
    errs := errors.NewErrorGroup()
    errs.Add(c.shutdownLoop())
    errs.Add(c.conn.Close())
    return errs.Finalize()
}

func (c *Conn) read(b []byte) (int, func() error) {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    c.mtx.Lock()
    defer c.mtx.Unlock()
    if c.is_shutdown {
        return 0, func() error { return io.EOF }
    }
    rv, errno := C.SSL_read(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
    if rv > 0 {
        return int(rv), nil
    }
    return 0, c.getErrorHandler(rv, errno)
}

func (c *Conn) Read(b []byte) (n int, err error) {
    if len(b) == 0 {
        return 0, nil
    }
    err = tryAgain
    for err == tryAgain {
        n, errcb := c.read(b)
        err = c.handleError(errcb)
        if err == nil {
            return n, c.flushOutputBuffer()
        }
        if err == io.ErrUnexpectedEOF {
            err = io.EOF
        }
    }
    return 0, err
}

func (c *Conn) write(b []byte) (int, func() error) {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    c.mtx.Lock()
    defer c.mtx.Unlock()
    if c.is_shutdown {
        err := SSLError.New("connection closed")
        return 0, func() error { return err }
    }
    rv, errno := C.SSL_write(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
    if rv > 0 {
        return int(rv), nil
    }
    return 0, c.getErrorHandler(rv, errno)
}

func (c *Conn) Write(b []byte) (written int, err error) {
    if len(b) == 0 {
        return 0, nil
    }
    err = tryAgain
    for err == tryAgain {
        n, errcb := c.write(b)
        err = c.handleError(errcb)
        if err == nil {
            return n, c.flushOutputBuffer()
        }
    }
    return 0, err
}

func (c *Conn) LocalAddr() net.Addr {
    return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
    return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
    return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
    return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
    return c.conn.SetWriteDeadline(t)
}
