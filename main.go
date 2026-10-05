// spill fetches a web page and the scripts it loads, and reports API keys and
// other secrets left in the client-side code.
//
// Only scan sites you own or are authorised to test.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("spill", flag.ContinueOnError)
	fl.SetOutput(stderr)
	jsonOut := fl.Bool("json", false, "print findings as JSON")
	allSev := fl.Bool("all", false, "also show keys that are public by design (Firebase, Stripe pk, ...)")
	noColor := fl.Bool("no-color", false, "disable colored output")
	showVersion := fl.Bool("version", false, "print version and exit")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "usage: spill [flags] <url>\n\n")
		fmt.Fprintf(stderr, "Fetches a page and its same-origin scripts and reports secrets in the\n")
		fmt.Fprintf(stderr, "client-side code. Only scan sites you own or are authorised to test.\n\n")
		fl.PrintDefaults()
		fmt.Fprintf(stderr, "\nexit status: 0 clean, 1 secret that should not be public, 2 error\n")
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "spill", version)
		return 0
	}
	if fl.NArg() != 1 {
		fl.Usage()
		return 2
	}
	target := fl.Arg(0)
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}

	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DisableKeepAlives:   false,
		MaxIdleConns:        16,
		IdleConnTimeout:     10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}}
	sources, err := gather(client, target)
	if err != nil {
		fmt.Fprintln(stderr, "spill:", err)
		return 2
	}
	findings := scanSources(sources)

	shown := findings
	if !*allSev {
		shown = shown[:0]
		for _, f := range findings {
			if !f.ClientSafe {
				shown = append(shown, f)
			}
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(struct {
			Version  string    `json:"version"`
			Sources  int       `json:"sources_scanned"`
			Findings []Finding `json:"findings"`
		}{version, len(sources), shown})
	} else {
		color := !*noColor && os.Getenv("NO_COLOR") == "" &&
			(forceColor() || stdout == os.Stdout && enableColor(os.Stdout))
		printReport(stdout, shown, len(sources), color, *allSev)
	}

	for _, f := range findings {
		if !f.ClientSafe {
			return 1
		}
	}
	return 0
}

var sevColor = map[severity]string{critical: "1;37;41", high: "1;31", medium: "33", low: "36"}

func paint(color bool, code, s string) string {
	if !color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func printReport(w io.Writer, findings []Finding, sources int, color, all bool) {
	fmt.Fprintf(w, "%s %s\n", paint(color, "1", "spill"), version)

	for _, f := range findings {
		tag := fmt.Sprintf(" %s ", strings.ToUpper(f.Severity.String()))
		label := f.Kind
		if f.ClientSafe {
			label += " (public by design)"
		}
		fmt.Fprintf(w, "\n  %s  %s\n", paint(color, sevColor[f.Severity], tag), paint(color, "1", label))
		fmt.Fprintf(w, "      %s\n", paint(color, "2", f.Source))
		fmt.Fprintf(w, "      found: %s\n", f.Match)
		for _, line := range wrap(f.Note, 84) {
			fmt.Fprintf(w, "      %s\n", paint(color, "2", line))
		}
	}

	fmt.Fprintf(w, "\n%d source(s) scanned\n", sources)
	if len(findings) == 0 {
		msg := "clean, no leaked secrets found"
		if !all {
			msg += " (use --all to also list keys that are public by design)"
		}
		fmt.Fprintln(w, paint(color, "32", msg))
		return
	}
	counts := map[severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []severity{critical, high, medium, low} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	fmt.Fprintln(w, paint(color, sevColor[worstOf(counts)], strings.Join(parts, "  ")))
}

func worstOf(c map[severity]int) severity {
	for _, s := range []severity{critical, high, medium, low} {
		if c[s] > 0 {
			return s
		}
	}
	return low
}

func wrap(s string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func forceColor() bool {
	v := os.Getenv("CLICOLOR_FORCE")
	return v != "" && v != "0"
}

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}
