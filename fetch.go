package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// source is one fetched document: the page itself or a script it loads.
type source struct {
	url  string
	body string
}

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	// inline config files a bundler often emits with secrets (env.js, config.js).
)

const maxBody = 8 << 20

// gather fetches the page at rawURL and every same-origin script it references.
func gather(client *http.Client, rawURL string) ([]source, error) {
	base, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	page, err := fetch(client, rawURL)
	if err != nil {
		return nil, err
	}
	sources := []source{{rawURL, page}}

	seen := map[string]bool{rawURL: true}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(page, -1) {
		ref, err := base.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		// Only same-origin scripts: third-party CDNs are not the site's secrets.
		if ref.Host != base.Host || seen[ref.String()] {
			continue
		}
		seen[ref.String()] = true
		if body, err := fetch(client, ref.String()); err == nil {
			sources = append(sources, source{ref.String(), body})
		}
		if len(sources) > 60 {
			break
		}
	}
	return sources, nil
}

func fetch(client *http.Client, u string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "spill/"+version+" (+https://github.com/ReazGan/spill)")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
