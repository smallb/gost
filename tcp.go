package gost

import (
	"net"

	"github.com/go-log/log"
)

// tcpTransporter is a raw TCP transporter.
type tcpTransporter struct{}

// TCPTransporter creates a raw TCP client.
func TCPTransporter() Transporter {
	return &tcpTransporter{}
}

func (tr *tcpTransporter) Dial(laddr, addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}
	if opts.Chain == nil {
		log.Logf("[tcp] opts.LocalAddr:%s", laddr)
		host, _, err := net.SplitHostPort(laddr)
		if err != nil {
			return net.DialTimeout("tcp", addr, timeout)
		}
		ip := net.ParseIP(host)
		if ip.IsLoopback() {
			host = ""
		}
		host = net.JoinHostPort(host, "0")

		laddr, err := net.ResolveTCPAddr("tcp", host)
		if err != nil {
			return nil, err
		}
		d := &net.Dialer{
			Timeout:   timeout,
			LocalAddr: laddr,
		}
		log.Logf("[tcp] 1 opts.LocalAddr:%s", laddr)
		defer log.Logf("[tcp] 2 opts.LocalAddr:%s", laddr)
		return d.Dial("tcp", addr)
	}
	return opts.Chain.Dial(addr)
}

func (tr *tcpTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *tcpTransporter) Multiplex() bool {
	return false
}

type tcpListener struct {
	net.Listener
}

// TCPListener creates a Listener for TCP proxy server.
func TCPListener(addr string) (Listener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := ReuseportListenTCP("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &tcpListener{Listener: tcpKeepAliveListener{ln}}, nil
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(KeepAliveTime)
	return tc, nil
}
