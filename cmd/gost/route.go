package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ginuerzh/gost"
	"github.com/go-log/log"
)

type stringList []string

func (l *stringList) String() string {
	return fmt.Sprintf("%s", *l)
}
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

type route struct {
	ServeNodes stringList
	ChainNodes stringList
	Retries    int
}

func (r *route) parseChain() (*gost.Chain, error) {
	chain := gost.NewChain()
	chain.Retries = r.Retries
	gid := 1 // group ID

	for _, ns := range r.ChainNodes {
		ngroup := gost.NewNodeGroup()
		ngroup.ID = gid
		gid++

		// parse the base nodes
		nodes, err := parseChainNode(ns)
		if err != nil {
			return nil, err
		}

		nid := 1 // node ID
		for i := range nodes {
			nodes[i].ID = nid
			nid++
		}
		ngroup.AddNode(nodes...)

		ngroup.SetSelector(nil,
			gost.WithFilter(
				&gost.FailFilter{
					MaxFails:    nodes[0].GetInt("max_fails"),
					FailTimeout: nodes[0].GetDuration("fail_timeout"),
				},
				&gost.InvalidFilter{},
			),
			gost.WithStrategy(gost.NewStrategy(nodes[0].Get("strategy"))),
		)

		if cfg := nodes[0].Get("peer"); cfg != "" {
			f, err := os.Open(cfg)
			if err != nil {
				return nil, err
			}

			peerCfg := newPeerConfig()
			peerCfg.group = ngroup
			peerCfg.baseNodes = nodes
			peerCfg.Reload(f)
			f.Close()

			go gost.PeriodReload(peerCfg, cfg)
		}

		chain.AddNodeGroup(ngroup)
	}

	return chain, nil
}

func parseChainNode(ns string) (nodes []gost.Node, err error) {
	node, err := gost.ParseNode(ns)
	if err != nil {
		return
	}

	users, err := parseUsers(node.Get("secrets"))
	if err != nil {
		return
	}
	if node.User == nil && len(users) > 0 {
		node.User = users[0]
	}
	serverName, sport, _ := net.SplitHostPort(node.Addr)
	if serverName == "" {
		serverName = "localhost" // default server name
	}

	rootCAs, err := loadCA(node.Get("ca"))
	if err != nil {
		return
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !node.GetBool("secure"),
		RootCAs:            rootCAs,
	}

	var host string

	var tr gost.Transporter
	switch node.Transport {
	case "tls":
		tr = gost.TLSTransporter()
	case "mtls":
		tr = gost.MTLSTransporter()
	default:
		tr = gost.TCPTransporter()
	}

	var connector gost.Connector
	switch node.Protocol {
	case "socks", "socks5":
		connector = gost.SOCKS5Connector(node.User)
	case "socks4":
		connector = gost.SOCKS4Connector()
	case "socks4a":
		connector = gost.SOCKS4AConnector()
	case "forward":
		connector = gost.ForwardConnector()
	case "http":
		fallthrough
	default:
		node.Protocol = "http" // default protocol is HTTP
		connector = gost.SOCKS5Connector(node.User)
	}

	timeout := node.GetInt("timeout")
	node.DialOptions = append(node.DialOptions,
		gost.TimeoutDialOption(time.Duration(timeout)*time.Second),
	)

	node.ConnectOptions = []gost.ConnectOption{
		gost.UserAgentConnectOption(node.Get("agent")),
	}

	if host == "" {
		host = node.Host
	}
	handshakeOptions := []gost.HandshakeOption{
		gost.AddrHandshakeOption(node.Addr),
		gost.HostHandshakeOption(host),
		gost.UserHandshakeOption(node.User),
		gost.TLSConfigHandshakeOption(tlsCfg),
		gost.IntervalHandshakeOption(time.Duration(node.GetInt("ping")) * time.Second),
		gost.TimeoutHandshakeOption(time.Duration(timeout) * time.Second),
		gost.RetryHandshakeOption(node.GetInt("retry")),
	}
	node.Client = &gost.Client{
		Connector:   connector,
		Transporter: tr,
	}

	node.Bypass = parseBypass(node.Get("bypass"))

	ips := parseIP(node.Get("ip"), sport)
	for _, ip := range ips {
		nd := node.Clone()
		nd.Addr = ip
		// override the default node address
		nd.HandshakeOptions = append(handshakeOptions, gost.AddrHandshakeOption(ip))
		// One node per IP
		nodes = append(nodes, nd)
	}
	if len(ips) == 0 {
		node.HandshakeOptions = handshakeOptions
		nodes = []gost.Node{node}
	}

	return
}

func (r *route) GenRouters() ([]router, error) {
	chain, err := r.parseChain()
	if err != nil {
		return nil, err
	}

	var rts []router

	for _, ns := range r.ServeNodes {
		node, err := gost.ParseNode(ns)
		if err != nil {
			return nil, err
		}
		authenticator, err := parseAuthenticator(node.Get("secrets"))
		if err != nil {
			return nil, err
		}
		if authenticator == nil && node.User != nil {
			kvs := make(map[string]string)
			kvs[node.User.Username()], _ = node.User.Password()
			authenticator = gost.NewLocalAuthenticator(kvs)
		}
		if node.User == nil {
			if users, _ := parseUsers(node.Get("secrets")); len(users) > 0 {
				node.User = users[0]
			}
		}
		certFile, keyFile := node.Get("cert"), node.Get("key")
		tlsCfg, err := tlsConfig(certFile, keyFile)
		if err != nil && certFile != "" && keyFile != "" {
			return nil, err
		}

		ttl, err := time.ParseDuration(node.Get("ttl"))
		if err != nil {
			ttl = time.Duration(node.GetInt("ttl")) * time.Second
		}

		var ln gost.Listener
		switch node.Transport {
		case "tls":
			ln, err = gost.TLSListener(node.Addr, tlsCfg)
		case "mtls":
			ln, err = gost.MTLSListener(node.Addr, tlsCfg)
		case "udp":
			ln, err = gost.UDPDirectForwardListener(node.Addr, &gost.UDPForwardListenConfig{
				TTL:       ttl,
				Backlog:   node.GetInt("backlog"),
				QueueSize: node.GetInt("queue"),
			})
		case "rudp":
			ln, err = gost.UDPRemoteForwardListener(node.Addr,
				chain,
				&gost.UDPForwardListenConfig{
					TTL:       ttl,
					Backlog:   node.GetInt("backlog"),
					QueueSize: node.GetInt("queue"),
				})
		default:
			ln, err = gost.TCPListener(node.Addr)
		}
		if err != nil {
			return nil, err
		}

		var handler gost.Handler
		switch node.Protocol {
		case "socks", "socks5":
			handler = gost.SOCKS5Handler()
		case "socks4", "socks4a":
			handler = gost.SOCKS4Handler()
		case "tcp":
			handler = gost.TCPDirectForwardHandler(node.Remote)
		case "rtcp":
			handler = gost.TCPRemoteForwardHandler(node.Remote)
		case "udp":
			handler = gost.UDPDirectForwardHandler(node.Remote)
		case "rudp":
			handler = gost.UDPRemoteForwardHandler(node.Remote)
		case "redirect":
			handler = gost.TCPRedirectHandler()
		default:
			// start from 2.5, if remote is not empty, then we assume that it is a forward tunnel.
			if node.Remote != "" {
				handler = gost.TCPDirectForwardHandler(node.Remote)
			} else {
				handler = gost.AutoHandler()
			}
		}

		var whitelist, blacklist *gost.Permissions
		if node.Values.Get("whitelist") != "" {
			if whitelist, err = gost.ParsePermissions(node.Get("whitelist")); err != nil {
				return nil, err
			}
		}
		if node.Values.Get("blacklist") != "" {
			if blacklist, err = gost.ParsePermissions(node.Get("blacklist")); err != nil {
				return nil, err
			}
		}

		node.Bypass = parseBypass(node.Get("bypass"))
		resolver := parseResolver(node.Get("dns"))
		hosts := parseHosts(node.Get("hosts"))
		ips := parseIP(node.Get("ip"), "")

		handler.Init(
			gost.AddrHandlerOption(ln.Addr().String()),
			gost.ChainHandlerOption(chain),
			gost.UsersHandlerOption(node.User),
			gost.AuthenticatorHandlerOption(authenticator),
			gost.TLSConfigHandlerOption(tlsCfg),
			gost.WhitelistHandlerOption(whitelist),
			gost.BlacklistHandlerOption(blacklist),
			gost.StrategyHandlerOption(gost.NewStrategy(node.Get("strategy"))),
			gost.MaxFailsHandlerOption(node.GetInt("max_fails")),
			gost.FailTimeoutHandlerOption(node.GetDuration("fail_timeout")),
			gost.BypassHandlerOption(node.Bypass),
			gost.ResolverHandlerOption(resolver),
			gost.HostsHandlerOption(hosts),
			gost.RetryHandlerOption(node.GetInt("retry")), // override the global retry option.
			gost.TimeoutHandlerOption(time.Duration(node.GetInt("timeout"))*time.Second),
			gost.ProbeResistHandlerOption(node.Get("probe_resist")),
			gost.KnockingHandlerOption(node.Get("knock")),
			gost.NodeHandlerOption(node),
			gost.IPsHandlerOption(ips),
			gost.TCPModeHandlerOption(node.GetBool("tcp")),
		)

		rt := router{
			node:     node,
			server:   &gost.Server{Listener: ln},
			handler:  handler,
			chain:    chain,
			resolver: resolver,
			hosts:    hosts,
		}
		rts = append(rts, rt)
	}

	return rts, nil
}

type router struct {
	node     gost.Node
	server   *gost.Server
	handler  gost.Handler
	chain    *gost.Chain
	resolver gost.Resolver
	hosts    *gost.Hosts
}

func (r *router) Serve() error {
	log.Logf("%s on %s", r.node.String(), r.server.Addr())
	return r.server.Serve(r.handler)
}

func (r *router) Close() error {
	if r == nil || r.server == nil {
		return nil
	}
	return r.server.Close()
}
