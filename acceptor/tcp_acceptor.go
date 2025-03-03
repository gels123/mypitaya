// Copyright (c) nano Author and TFG Co. All Rights Reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package acceptor

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/topfreegames/pitaya/v2/conn/codec"
	"github.com/topfreegames/pitaya/v2/constants"
	"github.com/topfreegames/pitaya/v2/logger"
)

// TcpAcceptor struct
type TcpAcceptor struct {
	addr          string
	connChan      chan PlayerConn
	listener      net.Listener
	running       bool
	certs         []tls.Certificate
	proxyProtocol bool
}

type tcpPlayerConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (t *tcpPlayerConn) RemoteAddr() net.Addr {
	return t.remoteAddr
}

// GetNextMessage reads the next message available in the stream
func (t *tcpPlayerConn) GetNextMessage() (b []byte, err error) {
	header, err := io.ReadAll(io.LimitReader(t.Conn, codec.HeadLength))
	if err != nil {
		return nil, err
	}
	// if the header has no data, we can consider it as a closed connection
	if len(header) == 0 {
		return nil, constants.ErrConnectionClosed
	}
	size, _, err := codec.ParseHeader(header)
	if err != nil {
		return nil, err
	}
	msg, err := io.ReadAll(io.LimitReader(t.Conn, int64(size)))
	if err != nil {
		return nil, err
	}
	if len(msg) < size {
		return nil, constants.ErrReceivedMsgSmallerThanExpected
	}
	return append(header, msg...), nil
}

// NewTcpAcceptor creates a new instance of tcp acceptor
func NewTcpAcceptor(addr string, certs ...string) *TcpAcceptor {
	certificates := []tls.Certificate{}
	if len(certs) != 2 && len(certs) != 0 {
		panic(constants.ErrIncorrectNumberOfCertificates)
	} else if len(certs) == 2 && certs[0] != "" && certs[1] != "" {
		cert, err := tls.LoadX509KeyPair(certs[0], certs[1])
		if err != nil {
			panic(fmt.Errorf("%w: %v", constants.ErrInvalidCertificates, err))
		}
		certificates = append(certificates, cert)
	}

	return NewTlsAcceptor(addr, certificates...)
}

func NewTlsAcceptor(addr string, certs ...tls.Certificate) *TcpAcceptor {
	return &TcpAcceptor{
		addr:          addr,
		connChan:      make(chan PlayerConn),
		running:       false,
		certs:         certs,
		proxyProtocol: false,
	}
}

// GetAddr returns the addr the acceptor will listen on
func (a *TcpAcceptor) GetAddr() string {
	if a.listener != nil {
		return a.listener.Addr().String()
	}
	return ""
}

// GetConnChan gets a connection channel
func (a *TcpAcceptor) GetConnChan() chan PlayerConn {
	return a.connChan
}

// Stop stops the acceptor
func (a *TcpAcceptor) Stop() {
	a.running = false
	a.listener.Close()
}

func (a *TcpAcceptor) hasTlsCertificates() bool {
	return len(a.certs) > 0
}

// ListenAndServe using tcp acceptor
func (a *TcpAcceptor) ListenAndServe() {
	listener := a.createBaseListener()

	if a.hasTlsCertificates() {
		listener = a.listenAndServeTls(listener)
	}

	a.listener = listener
	a.running = true
	a.serve()
}

// ListenAndServeTLS listens using tls
func (a *TcpAcceptor) ListenAndServeTLS(cert, key string) {
	listener := a.createBaseListener()

	crt, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		logger.Log.Fatalf("Failed to listen: %s", err.Error())
	}

	a.certs = append(a.certs, crt)

	a.listener = a.listenAndServeTls(listener)
	a.running = true
	a.serve()
}

// Create base listener
func (a *TcpAcceptor) createBaseListener() net.Listener {
	// Create raw listener
	listener, err := net.Listen("tcp", a.addr)
	if err != nil {
		logger.Log.Fatalf("Failed to listen: %s", err.Error())
	}

	// Wrap listener in ProxyProto
	listener = &ProxyProtocolListener{Listener: listener, proxyProtocolEnabled: &a.proxyProtocol}

	return listener
}

// ListenAndServeTLS listens using tls
func (a *TcpAcceptor) listenAndServeTls(listener net.Listener) net.Listener {
	tlsCfg := &tls.Config{Certificates: a.certs}
	tlsListener := tls.NewListener(listener, tlsCfg)

	return tlsListener
}

func (a *TcpAcceptor) EnableProxyProtocol() {
	a.proxyProtocol = true
}

func (a *TcpAcceptor) serve() {
	defer a.Stop()
	for a.running {
		conn, err := a.listener.Accept()
		if err != nil {
			logger.Log.Errorf("Failed to accept TCP connection: %s", err.Error())
			continue
		}
		a.connChan <- &tcpPlayerConn{
			Conn:       conn,
			remoteAddr: conn.RemoteAddr(),
		}
	}
}

func (a *TcpAcceptor) IsRunning() bool {
	return a.running
}

func (a *TcpAcceptor) GetConfiguredAddress() string {
	return a.addr
}
