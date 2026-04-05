package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"execution-substrate/es/app"
	"execution-substrate/es/config"
)

func main() {
	configPath := flag.String("config", "", "absolute path to ES config JSON")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	service, err := app.New(cfg)
	if err != nil {
		log.Fatalf("build app: %v", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout())
	defer startCancel()

	addr, err := service.Start(startCtx)
	if err != nil {
		log.Fatalf("start app: %v", err)
	}

	fmt.Fprintf(os.Stdout, "execution listening on %s\n", addr)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	<-signalCh

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout())
	defer shutdownCancel()

	if err := service.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown app: %v", err)
	}
}
