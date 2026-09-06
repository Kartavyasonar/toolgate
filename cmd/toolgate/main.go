package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kartavyasonar/toolgate/internal/mcp"
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
		fmt.Println("TODO: implement proxy")

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
	fmt.Println("  toolgate proxy ...")
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