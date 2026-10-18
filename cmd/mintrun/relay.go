package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

func relayTokenFn(rt *core.Runtime) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if tok := strings.TrimSpace(os.Getenv("MINTRUN_RELAY_TOKEN")); tok != "" {
			return tok, nil
		}
		vault, err := rt.Registry.Vault(rt.DefaultVault)
		if err != nil {
			return "", err
		}
		return vault.GetSecret(ctx, "relay")
	}
}

func configureRelay(rt *core.Runtime, rawURL string) error {
	if strings.TrimSpace(rawURL) == "" {
		return nil
	}
	rc, err := builtin.NewRelayClient(rawURL, relayTokenFn(rt))
	if err != nil {
		return err
	}
	rt.Relay = rc
	return nil
}

func cmdRelay(ctx context.Context, rt *core.Runtime, args []string) {
	if len(args) == 0 {
		fatal("usage: mintrun relay <serve|device> ...")
	}
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("relay serve", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:8443", "TCP address to listen on")
		certFile := fs.String("cert", "", "Path to TLS server certificate PEM")
		keyFile := fs.String("key", "", "Path to TLS server private key PEM")
		_ = fs.Parse(args[1:])
		if *certFile == "" || *keyFile == "" {
			fatal("usage: mintrun relay serve -listen <addr> -cert <cert.pem> -key <key.pem>")
		}
		if err := serveRelay(ctx, rt, *listen, *certFile, *keyFile); err != nil {
			fatal("relay serve: %v", err)
		}

	case "device":
		if len(args) < 2 {
			fatal("usage: mintrun relay device <add|remove|list> [name]")
		}
		switch args[1] {
		case "add":
			if len(args) < 3 {
				fatal("usage: mintrun relay device add <name>")
			}
			tok, dev, err := builtin.AddRelayDevice(rt.HomeDir, args[2])
			if err != nil {
				fatal("relay device add: %v", err)
			}
			fmt.Printf("Enrolled relay device %q (sha256:%s).\nDevice token (save now; shown only once):\n%s\n", dev.Name, dev.TokenSHA256, tok)

		case "remove", "rm":
			if len(args) < 3 {
				fatal("usage: mintrun relay device remove <name>")
			}
			if err := builtin.RemoveRelayDevice(rt.HomeDir, args[2]); err != nil {
				fatal("relay device remove: %v", err)
			}
			fmt.Printf("Removed relay device %q.\n", args[2])

		case "list", "ls":
			devs, err := builtin.ListRelayDevices(rt.HomeDir)
			if err != nil {
				fatal("relay device list: %v", err)
			}
			if len(devs) == 0 {
				fmt.Println("No relay devices enrolled.")
				return
			}
			fmt.Printf("%-20s %-22s %s\n", "NAME", "CREATED", "TOKEN_SHA256")
			for _, d := range devs {
				fmt.Printf("%-20s %-22s %s\n", d.Name, d.CreatedAt, d.TokenSHA256)
			}

		default:
			fatal("unknown relay device action %q (use add, remove, or list)", args[1])
		}

	default:
		fatal("unknown relay action %q (use serve or device)", args[0])
	}
}

func serveRelay(ctx context.Context, rt *core.Runtime, listenAddr, certFile, keyFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	pin, err := builtin.RelayCertPin(certPEM)
	if err != nil {
		return err
	}
	kp, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{kp},
		MinVersion:   tls.VersionTLS13,
	})
	srv := builtin.NewRelayServer(rt)
	defer srv.Close()
	httpSrv := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	fmt.Printf("mintrun relay listening on https://%s#sha256=%s\n", ln.Addr().String(), pin)

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.Serve(tlsLn)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
