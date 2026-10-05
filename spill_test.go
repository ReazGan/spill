package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mockSite() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!doctype html><html><head>
			<script src="/assets/app.js"></script>
			<script src="https://cdn.example.net/third-party.js"></script>
			</head><body>
			<script>const stripe = "sk_live_AAAAAAAAAAAAAAAAAAAA";</script>
			</body></html>`))
	})
	mux.HandleFunc("/assets/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`const AWS_SECRET_ACCESS_KEY="abcdefghijklmnopqrstuvwxyz0123456789ABCD";
			const firebaseConfig={apiKey:"AIzaSyA1234567890abcdefghijklmnopqrstuvw"};
			const pk="pk_live_1234567890abcdefghij";`))
	})
	return httptest.NewServer(mux)
}

func testClient() *http.Client { return &http.Client{Timeout: 5 * time.Second} }

func TestGatherFollowsSameOriginScripts(t *testing.T) {
	ts := mockSite()
	defer ts.Close()
	sources, err := gather(testClient(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	// page + /assets/app.js, but NOT the cross-origin cdn script
	if len(sources) != 2 {
		t.Fatalf("sources = %d, want 2 (cross-origin script must be skipped)", len(sources))
	}
}

func TestFindsLeakedSecrets(t *testing.T) {
	ts := mockSite()
	defer ts.Close()
	sources, _ := gather(testClient(), ts.URL)
	findings := scanSources(sources)

	kinds := map[string]severity{}
	for _, f := range findings {
		kinds[f.Kind] = f.Severity
	}
	if kinds["Stripe secret key"] != critical {
		t.Error("Stripe sk_live not flagged critical")
	}
	if kinds["AWS secret access key"] != critical {
		t.Error("AWS secret not flagged critical")
	}
}

func TestPublicByDesignMarked(t *testing.T) {
	ts := mockSite()
	defer ts.Close()
	findings := scanSources(mustGather(t, ts.URL))
	var firebase *Finding
	for i := range findings {
		if findings[i].Kind == "Firebase config" {
			firebase = &findings[i]
		}
	}
	if firebase == nil || !firebase.ClientSafe {
		t.Error("Firebase apiKey should be marked public by design")
	}
}

func TestRedactHidesKey(t *testing.T) {
	r := redact("sk_live_AAAAAAAAAAAAAAAAAAAA")
	if strings.Contains(r, "AAAAAAAAAAAA") || !strings.Contains(r, "***") {
		t.Errorf("not redacted: %q", r)
	}
}

func TestDedup(t *testing.T) {
	src := []source{{"a", "sk_live_SAME1234567890abcd sk_live_SAME1234567890abcd"}}
	if n := len(scanSources(src)); n != 1 {
		t.Errorf("duplicate match not deduped: %d", n)
	}
}

func TestRunExitCodes(t *testing.T) {
	ts := mockSite()
	defer ts.Close()
	var out strings.Builder
	if code := run([]string{"-no-color", ts.URL}, &out, &out); code != 1 {
		t.Errorf("leaky site exit = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "Stripe secret key") {
		t.Errorf("output missing finding:\n%s", out.String())
	}

	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer clean.Close()
	out.Reset()
	if code := run([]string{"-no-color", clean.URL}, &out, &out); code != 0 {
		t.Errorf("clean site exit = %d, want 0", code)
	}
}

func TestOnlyPublicKeysExitZero(t *testing.T) {
	// a site with only public-by-design keys must not fail the exit code
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<script>const k="pk_live_1234567890abcdefghij";</script>`))
	}))
	defer ts.Close()
	var out strings.Builder
	if code := run([]string{"-no-color", "-all", ts.URL}, &out, &out); code != 0 {
		t.Errorf("public-only exit = %d, want 0", code)
	}
}

func mustGather(t *testing.T, u string) []source {
	t.Helper()
	s, err := gather(testClient(), u)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
