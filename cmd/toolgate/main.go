package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/kartavyasonar/toolgate/internal/mcp"
	"github.com/kartavyasonar/toolgate/internal/scanner"
)

func usage() {
	fmt.Fprintf(os.Stderr, `ToolGate — security scanner and runtime policy gateway for MCP servers

Usage:
  toolgate scan --target <url>
  toolgate proxy

Commands:
  scan    Scan an MCP server tool list for risky patterns
  proxy   Runtime policy gateway (not yet implemented)

Flags:
  scan --target  JSON-RPC HTTP URL of the MCP server (required)
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "proxy":
		fmt.Println("TODO: implement proxy")
	case "-h", "-help", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage
	target := fs.String("target", "", "MCP server JSON-RPC HTTP URL")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse scan flags: %w", err)
	}
	if *target == "" {
		usage()
		return fmt.Errorf("--target is required")
	}

	client := mcp.NewClient(*target)
	result, err := client.ListTools(context.Background())
	if err != nil {
		return fmt.Errorf("list tools: %w", err)
	}

	findings := scanner.Scan(result.Tools)
	if len(findings) == 0 {
		fmt.Println("No findings.")
		return nil
	}

	for i, finding := range findings {
		fmt.Printf("%d. [%s] tool=%s rule=%s message=%s\n",
			i+1, finding.Severity, finding.Tool, finding.Rule, finding.Message)
	}
	return nil
}
