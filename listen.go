package gost

import (
	"net"

	"github.com/libp2p/go-reuseport"
)

var Reuseport bool

// ReuseportListen announces on the local network address by reuseport
//
// The network must be "tcp", "tcp4", "tcp6", "unix" or "unixpacket".
//
// For TCP networks, if the host in the address parameter is empty or
// a literal unspecified IP address, Listen listens on all available
// unicast and anycast IP addresses of the local system.
// To only use IPv4, use network "tcp4".
// The address can use a host name, but this is not recommended,
// because it will create a listener for at most one of the host's IP
// addresses.
// If the port in the address parameter is empty or "0", as in
// "127.0.0.1:" or "[::1]:0", a port number is automatically chosen.
// The Addr method of Listener can be used to discover the chosen
// port.
//
// See func Dial for a description of the network and address
// parameters.
func ReuseportListen(network string, address string) (net.Listener, error) {
	if Reuseport {
		return reuseport.Listen(network, address)
	}
	return net.Listen(network, address)
}

// ReuseportListenUDP acts like ListenPacket for UDP networks.
//
// The network must be a UDP network name; see func Dial for details.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ReuseportListenUDP listens on all available IP addresses of the local system
// except multicast IP addresses.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func ReuseportListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	if Reuseport {
		strAddr := ""
		if nil != laddr {
			strAddr = laddr.String()
		}
		conn, err := reuseport.ListenPacket(network, strAddr)
		return conn.(*net.UDPConn), err
	}
	return net.ListenUDP(network, laddr)
}

// ReuseportListenTCP acts like Listen for TCP networks.
//
// The network must be a TCP network name; see func Dial for details.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ReuseportListenTCP listens on all available unicast and anycast IP addresses
// of the local system.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func ReuseportListenTCP(network string, laddr *net.TCPAddr) (*net.TCPListener, error) {
	if Reuseport {
		strAddr := ""
		if nil != laddr {
			strAddr = laddr.String()
		}
		conn, err := reuseport.Listen(network, strAddr)
		return conn.(*net.TCPListener), err
	}
	return net.ListenTCP(network, laddr)
}
