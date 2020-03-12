package main

import (
	"C"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"net/http"
	_ "net/http/pprof"

	"github.com/ginuerzh/gost"
	"github.com/go-log/log"
	"github.com/juju/ratelimit"
)
import (
	"os/signal"
	"syscall"
)

var (
	configureFile string
	baseCfg       = &baseConfig{}
	pprofAddr     string
	pprofEnabled  = os.Getenv("PROFILING") != ""
	isFlagSet     bool
	grouters 	  []router
)

func parseCommand(cmd string) error {
	gost.SetLogger(&gost.LogLogger{})

	var (
		printVersion bool
		limit        int64
	)

	baseCfg.route.ChainNodes = baseCfg.route.ChainNodes[0:0]
	baseCfg.route.ServeNodes = baseCfg.route.ServeNodes[0:0]

	if !isFlagSet {
		isFlagSet = true
		flag.Var(&baseCfg.route.ChainNodes, "F", "forward address, can make a forward chain")
		flag.Var(&baseCfg.route.ServeNodes, "L", "listen address, can listen on multiple ports (required)")
		flag.StringVar(&configureFile, "C", "", "configure file")
		flag.BoolVar(&baseCfg.Debug, "D", false, "enable debug log")
		flag.BoolVar(&baseCfg.Reuseport, "R", false, "enable Reuseport")
		flag.BoolVar(&printVersion, "V", false, "print version")
		flag.Int64Var(&limit, "M", 0, "limit flow (kb)")
		if pprofEnabled {
			flag.StringVar(&pprofAddr, "P", ":6060", "profiling HTTP server address")
		}
	}

	// flag.Parse()
	err := flag.CommandLine.Parse(strings.Split(cmd, " "))
	if err != nil {
		log.Log(err)
		return err
	}

	if printVersion {
		fmt.Fprintf(os.Stderr, "gost %s (%s %s/%s)\n",
			gost.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return errors.New("printVersion")
	}

	if configureFile != "" {
		_, err := parseBaseConfig(configureFile)
		if err != nil {
			log.Log(err)
			return err
		}
	}
	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		return errors.New("flag.NFlag() == 0")
	}

	if 0 < limit {
		gost.LimitBucket = ratelimit.NewBucketWithRate((float64)(limit*1024), limit*1024)
	}
	return nil
}

func startEx() error {
	gost.Debug = baseCfg.Debug
	gost.Reuseport = baseCfg.Reuseport

	rts, err := baseCfg.route.GenRouters()
	if err != nil {
		return err
	}
	grouters = append(grouters, rts...)

	for _, route := range baseCfg.Routes {
		rts, err := route.GenRouters()
		if err != nil {
			return err
		}
		grouters = append(grouters, rts...)
	}

	if len(grouters) == 0 {
		return errors.New("invalid config")
	}
	for i := range grouters {
		go grouters[i].Serve()
	}

	return nil
}
//export stop
func stop() {
	for i := range grouters {
		go grouters[i].Close()
	}
}

//export start
func start(cmd string) int {
	if pprofEnabled {
		go func() {
			log.Log("profiling server on", pprofAddr)
			log.Log(http.ListenAndServe(pprofAddr, nil))
		}()
	}

	err := parseCommand(cmd)
	if err != nil {
		log.Log(err)
		return 1
	}

	// NOTE: as of 2.6, you can use custom cert/key files to initialize the default certificate.
	tlsConfig, err := tlsConfig(defaultCertFile, defaultKeyFile)
	if err != nil {
		// generate random self-signed certificate.
		cert, err := gost.GenCertificate()
		if err != nil {
			log.Log(err)
			return 1
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else {
		log.Log("load TLS certificate files OK")
	}

	gost.DefaultTLSConfig = tlsConfig

	if err := startEx(); err != nil {
		log.Log(err)
		return 1
	}

	return 0
}

func main() {
	count := len(os.Args)
	if count < 1 {
		return
	}

	var command string
	for index := 1; index < count; index++ {
		command += os.Args[index]
		command += " "
	}

	start(command)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
