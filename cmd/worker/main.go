package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/linkflow/engine/internal/version"
	"github.com/linkflow/engine/internal/worker"
	"github.com/linkflow/engine/internal/worker/executor"
)

func main() {
	var (
		port         = flag.Int("port", 7236, "Worker service port")
		taskQueue    = flag.String("task-queue", "default", "Task queue name")
		matchingAddr = flag.String("matching-addr", "localhost:7235", "Matching service address")
		numWorkers   = flag.Int("num-workers", 4, "Number of worker goroutines")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	printBanner("Worker", logger)

	_ = *port
	_ = *numWorkers

	svc := worker.NewService(worker.Config{
		TaskQueue:    *taskQueue,
		Identity:     fmt.Sprintf("worker-%d", os.Getpid()),
		MatchingAddr: *matchingAddr,
		PollInterval: time.Second,
		Logger:       logger,
	})

	httpExecutor := executor.NewHTTPExecutor()
	svc.RegisterExecutor(httpExecutor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.Start(ctx); err != nil {
		logger.Error("failed to start worker service", slog.String("error", err.Error()))
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
		cancel()
		_ = svc.Stop()
	}()

	logger.Info("worker pool started",
		slog.String("task_queue", *taskQueue),
		slog.String("matching_addr", *matchingAddr),
		slog.Int("num_workers", *numWorkers),
	)

	<-ctx.Done()
	logger.Info("worker service stopped")
}

func printBanner(service string, logger *slog.Logger) {
	logger.Info(fmt.Sprintf("LinkFlow %s Service", service),
		slog.String("version", version.Version),
		slog.String("commit", version.GitCommit),
		slog.String("build_time", version.BuildTime),
	)
}
