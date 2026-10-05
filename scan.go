package main

import "sort"

// Finding is one secret found in one source.
type Finding struct {
	Kind       string   `json:"kind"`
	Severity   severity `json:"severity"`
	Source     string   `json:"source"`
	Match      string   `json:"match"`
	Note       string   `json:"note"`
	ClientSafe bool     `json:"public_by_design"`
}

// scanSources runs every pattern over every source and dedupes by (kind, match).
func scanSources(sources []source) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, src := range sources {
		for _, p := range patterns {
			for _, m := range p.re.FindAllString(src.body, -1) {
				key := p.name + "|" + m
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Finding{
					Kind:       p.name,
					Severity:   p.severity,
					Source:     src.url,
					Match:      redact(m),
					Note:       p.note,
					ClientSafe: p.clientSafe,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// redact keeps enough of a match to recognise it without printing a usable key.
func redact(s string) string {
	s = oneLine(s)
	if len(s) <= 12 {
		return s[:len(s)/2] + "***"
	}
	return s[:8] + "***" + s[len(s)-4:]
}

func oneLine(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		out = append(out, r)
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return string(out)
}
