package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kartavyasonar/toolgate/internal/audit"
	"github.com/kartavyasonar/toolgate/internal/mcp"
	"github.com/kartavyasonar/toolgate/internal/policy"
	"github.com/kartavyasonar/toolgate/internal/proxy"
	"github.com/kartavyasonar/toolgate/internal/report"
	"github.com/kartavyasonar/toolgate/internal/scanner"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		scanFlags := flag.NewFlagSet("scan", flag.ExitOnError)
		target := scanFlags.String("target", "", "MCP server URL")
		format := scanFlags.String("format", "text", "Output format: text, json, or markdown")
		output := scanFlags.String("output", "", "File path to write report")
		_ = scanFlags.Parse(os.Args[2:])

		if *target == "" {
			fmt.Println("--target is required")
			os.Exit(1)
		}

		if err := runScan(*target, *format, *output); err != nil {
			fmt.Println("scan failed:", err)
			os.Exit(1)
		}

	case "proxy":
		proxyFlags := flag.NewFlagSet("proxy", flag.ExitOnError)
		listen := proxyFlags.String("listen", "127.0.0.1:9090", "Proxy listen address")
		target := proxyFlags.String("target", "http://127.0.0.1:8000/mcp", "Upstream MCP server URL")
		policyPath := proxyFlags.String("policy", "policies/default.yaml", "Path to policy YAML file")
		_ = proxyFlags.Parse(os.Args[2:])

		if err := runProxy(*listen, *target, *policyPath); err != nil {
			fmt.Println("proxy failed:", err)
			os.Exit(1)
		}

	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("ToolGate")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  toolgate scan --target http://127.0.0.1:8000/mcp [--format text|json|markdown] [--output path]")
	fmt.Println("  toolgate proxy [--listen 127.0.0.1:9090] [--target http://127.0.0.1:8000/mcp] [--policy policies/default.yaml]")
}

func runScan(target, formatStr, outputPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client := mcp.NewClient(target)
	result, err := client.ListTools(ctx)
	if err != nil {
		return err
	}

	findings := scanner.Scan(result.Tools)
	scanner.SortFindings(findings)
	scoreResult := scanner.Score(findings)

	format, err := report.ParseFormat(formatStr)
	if err != nil {
		return err
	}

	rep := report.New(target, scoreResult)
	rendered, err := rep.Render(format)
	if err != nil {
		return err
	}

	if outputPath == "" {
		fmt.Println(rendered)
	} else {
		if err := os.WriteFile(outputPath, []byte(rendered+"\n"), 0644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", outputPath)
	}

	return nil
}

func runProxy(listen, target, policyPath string) error {
	p, err := policy.Load(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	logger, err := audit.NewLogger("")
	if err != nil {
		return fmt.Errorf("init audit logger: %w", err)
	}
	defer logger.Close()

	srv := proxy.New(proxy.Config{
		ListenAddr:  listen,
		TargetURL:   target,
		Policy:      p,
		AuditLogger: logger,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown (Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down proxy...")
		cancel()
	}()

	return srv.Start(ctx)
}