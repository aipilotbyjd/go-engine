package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/linkflow/engine/internal/version"
)

func main() {
	var (
		port         = flag.Int("port", 7239, "Edge proxy port")
		upstreamAddr = flag.String("upstream-addr", "localhost:7233", "Upstream frontend address")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	printBanner("Edge", logger)

	_ = *port
	_ = *upstreamAddr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
		cancel()
	}()

	logger.Info("edge proxy started", slog.Int("port", *port), slog.String("upstream_addr", *upstreamAddr))

	<-ctx.Done()
	logger.Info("edge proxy stopped")
}

func printBanner(service string, logger *slog.Logger) {
	logger.Info(fmt.Sprintf("LinkFlow %s Service", service),
		slog.String("version", version.Version),
		slog.String("commit", version.GitCommit),
		slog.String("build_time", version.BuildTime),
	)
}
