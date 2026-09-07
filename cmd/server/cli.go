package main

import (
	"log"
	"os"

	"github.com/d1nfinite/go-icmpshell/server"
	"github.com/urfave/cli"
)

// version 为默认版本号,可在编译时通过 -ldflags "-X main.version=x.y.z" 覆盖
var version = "v2.0.1"

var (
	app = &cli.App{
		Name:    "go-icmpshell-server",
		Usage:   "go-icmpshell server (ICMP command & control listener)",
		Version: version,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "logs",
				Usage: "Enable ICMP send/recv logs",
			},
			cli.StringFlag{
				Name:  "token",
				Usage: "Handshake token",
				Value: "go-icmpshell",
			},
		},
		Action: func(c *cli.Context) error {
			s, err := server.NewServer(server.WithToken([]byte(c.String("token"))), server.WithLogs(c.Bool("logs")))
			if err != nil {
				log.Fatal(err)
			}

			go s.ListenICMP()
			err = s.StartupShell()
			if err != nil {
				log.Fatal(err)
			}

			return nil
		},
	}
)

func main() {
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
