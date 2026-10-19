package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

const watchUsage = "usage: mintrun watch [-http 127.0.0.1:0]"

func isLoopbackHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func cmdWatch(ctx context.Context, rt *core.Runtime, args []string) {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	httpAddr := fs.String("http", "127.0.0.1:0", "Loopback HTTP dashboard address (empty to disable)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fatal(watchUsage)
	}
	if *httpAddr != "" && !isLoopbackHost(*httpAddr) {
		fatal("watch -http must bind a loopback address (e.g. 127.0.0.1:0)")
	}

	srv := builtin.NewWatchServer(rt)
	srv.Out = os.Stderr
	unixLn, err := srv.ListenUnix()
	if err != nil {
		fatal("watch: %v", err)
	}
	defer srv.Close()

	var httpSrv *http.Server
	if *httpAddr != "" {
		httpLn, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			fatal("watch http listen: %v", err)
		}
		defer httpLn.Close()
		httpSrv = &http.Server{
			Handler:           srv,
			ReadHeaderTimeout: 5 * time.Second,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
		go func() {
			_ = httpSrv.Serve(httpLn)
		}()
		// The token rides in the #fragment, which a browser never sends to a server.
		fmt.Printf("mintrun watch listening on app.sock (dashboard: %s)\n", srv.DashboardURL(httpLn.Addr().String()))
	} else {
		fmt.Println("mintrun watch listening on app.sock")
	}

	_ = srv.ServeUnix(ctx, unixLn)
	if httpSrv != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		fatal("watch: %v", err)
	}
}
