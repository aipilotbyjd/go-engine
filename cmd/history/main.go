package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/linkflow/engine/internal/history"
	"github.com/linkflow/engine/internal/history/shard"
	"github.com/linkflow/engine/internal/version"
)

func main() {
	var (
		port       = flag.Int("port", 7234, "gRPC server port")
		shardCount = flag.Int("shard-count", 16, "Number of shards")
		dbURL      = flag.String("db-url", "postgres://localhost:5432/linkflow", "Database URL")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	printBanner("History", logger)

	_ = *dbURL

	shardController := shard.NewController(*shardCount)

	svc := history.NewService(
		&shardControllerAdapter{shardController},
		nil,
		nil,
		logger,
	)

	server := grpc.NewServer()
	reflection.Register(server)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		logger.Error("failed to listen", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.Start(ctx); err != nil {
		logger.Error("failed to start service", slog.String("error", err.Error()))
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
		cancel()
		_ = svc.Stop(ctx)
		server.GracefulStop()
	}()

	logger.Info("starting gRPC server", slog.Int("port", *port), slog.Int("shard_count", *shardCount))

	go func() {
		if err := server.Serve(lis); err != nil {
			logger.Error("server failed", slog.String("error", err.Error()))
			cancel()
		}
	}()

	<-ctx.Done()
	logger.Info("history service stopped")
}

func printBanner(service string, logger *slog.Logger) {
	logger.Info(fmt.Sprintf("LinkFlow %s Service", service),
		slog.String("version", version.Version),
		slog.String("commit", version.GitCommit),
		slog.String("build_time", version.BuildTime),
	)
}

type shardControllerAdapter struct {
	ctrl *shard.Controller
}

func (a *shardControllerAdapter) GetShardForExecution(key history.ExecutionKey) (history.Shard, error) {
	s, err := a.ctrl.GetShardForExecution(key)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (a *shardControllerAdapter) GetShardIDForExecution(key history.ExecutionKey) int32 {
	return a.ctrl.GetShardIDForExecution(key)
}

func (a *shardControllerAdapter) Stop() {
	a.ctrl.Stop()
}
