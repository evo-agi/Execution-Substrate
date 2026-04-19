package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"execution-substrate/ars/app"
	"execution-substrate/ars/config"
)

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "", "Absolute path to the ARS JSON config file")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "-config is required")
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}

	service, err := app.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build app: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr, err := service.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start app: %v\n", err)
		return 1
	}

	log.Printf("artifact-registry listening on %s", addr)

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout())
	defer cancel()

	if err := service.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "shutdown app: %v\n", err)
		return 1
	}

	return 0
}
