package cli

// The window drives these two commands instead of calling the API directly, for
// the same reason it drives `verify`: one validation path, one behaviour
// (ADR-0008). The token travels in the environment of the process that started
// the window, never in a URL.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// runRequests lists what is waiting for a decision.
func runRequests(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("requests", flag.ContinueOnError)
	flags.SetOutput(stderr)

	address := flags.String("api", "127.0.0.1:0", "address of the local API")
	asJSON := flags.Bool("json", true, "machine-readable output")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	token, err := readToken()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUnverified
	}

	request, err := http.NewRequest(http.MethodGet, "http://"+*address+"/v1/requests", nil)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	request.Header.Set("X-Firma-Token", token)

	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		fmt.Fprintf(stderr, "cannot reach the local API at %s: %v\n", *address, err)
		return exitUnverified
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUnverified
	}
	if response.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "%s\n", body)
		return exitUnverified
	}

	if *asJSON {
		_, _ = stdout.Write(body)
		return exitOK
	}

	var envelope struct {
		Data []struct {
			ID        string `json:"ID"`
			Path      string `json:"Path"`
			ExpiresAt string `json:"ExpiresAt"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUnverified
	}
	if len(envelope.Data) == 0 {
		fmt.Fprintln(stdout, "no pending requests")
		return exitOK
	}
	for _, pending := range envelope.Data {
		fmt.Fprintf(stdout, "%-16s %s\n", pending.ID[:min(16, len(pending.ID))], pending.Path)
	}
	return exitOK
}

// runDecide records the answer for a request.
func runDecide(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("decide", flag.ContinueOnError)
	flags.SetOutput(stderr)

	address := flags.String("api", "127.0.0.1:0", "address of the local API")
	secret := flags.String("secret", "", "approval secret shown by the handler")
	approved := flags.Bool("approved", false, "approve the request")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: pignus decide <id> --secret <secret> --approved")
		return exitUsage
	}
	if *secret == "" {
		fmt.Fprintln(stderr, "the approval secret is required")
		return exitUsage
	}

	token, err := readToken()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUnverified
	}

	payload, err := json.Marshal(map[string]any{"secret": *secret, "approved": *approved})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}

	url := "http://" + *address + "/v1/requests/" + flags.Arg(0) + "/decision"
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Firma-Token", token)

	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		fmt.Fprintf(stderr, "cannot reach the local API: %v\n", err)
		return exitUnverified
	}
	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "%s\n", body)
		return exitInvalid
	}
	fmt.Fprintln(stdout, "recorded")
	return exitOK
}

// readToken reads the local token written by the running server.
func readToken() (string, error) {
	if explicit := os.Getenv("PIGNUS_TOKEN"); explicit != "" {
		return explicit, nil
	}

	path, err := tokenLocation()
	if err != nil {
		return "", err
	}
	content, err := os.ReadFile(path + string(os.PathSeparator) + "token")
	if err != nil {
		return "", fmt.Errorf("no running pignus server (looked for %s/token): %w", path, err)
	}
	return string(content), nil
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
