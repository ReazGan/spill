package main

import "regexp"

type severity int

const (
	low severity = iota + 1
	medium
	high
	critical
)

func (s severity) String() string {
	switch s {
	case critical:
		return "critical"
	case high:
		return "high"
	case medium:
		return "medium"
	}
	return "low"
}

func (s severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// secretPattern describes one kind of credential found in client-side code.
// clientSafe marks keys that are *designed* to be public (Stripe publishable
// keys, Firebase apiKey, Google Maps browser keys): those are reported at low
// severity as a reminder to restrict them, not as a leak.
type secretPattern struct {
	name       string
	re         *regexp.Regexp
	severity   severity
	note       string
	clientSafe bool
}

var patterns = []secretPattern{
	// Never belong in client-side code.
	{"AWS secret access key", regexp.MustCompile(`(?i)aws_?secret_?access_?key["'\s:=]{1,6}([A-Za-z0-9/+]{40})`), critical,
		"An AWS secret key in shipped code is full account access. Rotate it now.", false},
	{"AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), critical,
		"An AWS access key id in client code is paired with a secret somewhere. Rotate the key pair.", false},
	{"Stripe secret key", regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{16,}\b`), critical,
		"A Stripe SECRET key (sk_live) in the browser lets anyone charge and refund on your account. Rotate it immediately.", false},
	{"Stripe restricted key", regexp.MustCompile(`\brk_live_[A-Za-z0-9]{16,}\b`), critical,
		"A Stripe restricted live key is shipped to the browser. Rotate it.", false},
	{"OpenAI key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`), critical,
		"An OpenAI key in the browser can be drained by anyone who views source. Move calls server-side and rotate.", false},
	{"Anthropic key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`), critical,
		"An Anthropic key in the browser can be drained. Move calls server-side and rotate.", false},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`), critical,
		"A GitHub token in client code grants repo access. Rotate it.", false},
	{"Supabase service_role key", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]*service_role[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{10,}`), critical,
		"The Supabase service_role key bypasses all row-level security. In the browser it is full database access. Rotate it and use the anon key.", false},
	{"Google service account key", regexp.MustCompile(`"private_key":\s*"-----BEGIN PRIVATE KEY-----`), critical,
		"A Google service account private key is embedded in the page. Rotate the key and remove it from client code.", false},
	{"private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), critical,
		"A private key is embedded in client-side code. Rotate it and serve it only server-side.", false},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), high,
		"A Slack token in client code can post and read in your workspace. Rotate it.", false},
	{"SendGrid key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`), high,
		"A SendGrid key in the browser lets anyone send mail as you. Rotate it.", false},
	{"Twilio account SID", regexp.MustCompile(`\bAC[0-9a-f]{32}\b`), high,
		"A Twilio SID in client code is usually paired with an auth token nearby. Check and rotate.", false},

	// Public by design, but worth restricting.
	{"Stripe publishable key", regexp.MustCompile(`\bpk_live_[A-Za-z0-9]{16,}\b`), low,
		"A Stripe publishable key is meant to be public; this is only a note that it is live, not test.", true},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), medium,
		"A Google API key is visible. These are meant to be public but MUST be restricted by HTTP referrer and API, or anyone can run up your bill.", true},
	{"Firebase config", regexp.MustCompile(`(?i)apiKey["'\s:=]{1,6}["']AIza[0-9A-Za-z_-]{35}`), low,
		"A Firebase apiKey is public by design; make sure your Firestore/Storage security rules are not left open.", true},
	{"Mapbox token", regexp.MustCompile(`\bpk\.eyJ[A-Za-z0-9_-]{20,}\b`), low,
		"A Mapbox public token is meant to be public; restrict it by URL in your Mapbox account.", true},
	{"Algolia app/key", regexp.MustCompile(`(?i)algolia[^"'\n]{0,30}["'][A-Za-z0-9]{32}["']`), low,
		"An Algolia search key is usually public; make sure it is the search-only key, not the admin key.", true},
	{"Sentry DSN", regexp.MustCompile(`https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/\d+`), low,
		"A Sentry DSN is public by design; this is only a note.", true},
}
