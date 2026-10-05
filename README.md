# spill

[![CI](https://github.com/ReazGan/spill/actions/workflows/ci.yml/badge.svg)](https://github.com/ReazGan/spill/actions/workflows/ci.yml)

Find the API keys you shipped to the browser.

Apps built fast, with a bundler or an AI coding tool, have a habit of baking a
secret straight into the frontend: a Stripe `sk_live`, an OpenAI key, an AWS
secret, a Supabase `service_role`. Anyone can open dev tools and read them.
spill fetches a page and the scripts it loads and tells you what's in there.

Single binary. Fetches only the page and its own scripts, nothing else.

![spill finding an OpenAI key and a Stripe secret key in a site's JavaScript](https://raw.githubusercontent.com/ReazGan/spill/main/docs/screenshot.svg)

> Only scan sites you own or are authorised to test.

## Install

Grab a binary from [Releases](https://github.com/ReazGan/spill/releases), or with
Go 1.22+:

```
go install github.com/ReazGan/spill@latest
```

## Usage

```
spill example.com                scan a site
spill https://app.example.com    scan a specific URL
spill --all example.com          also list keys that are public by design
spill --json example.com         machine-readable output
```

Exit status is `0` when nothing that should be private was found, `1` when a
real leak is found, and `2` on error.

## What it finds

**Should never be in the browser** (reported by default, matches are redacted):

Stripe `sk_live`/`rk_live`, OpenAI and Anthropic keys, AWS access/secret keys,
Supabase `service_role`, Google service-account and other private keys, GitHub
tokens, Slack tokens, SendGrid keys, Twilio SIDs.

**Public by design** (shown only with `--all`, as a reminder to restrict them):

Stripe publishable keys, Firebase config, Google Maps/browser API keys, Mapbox
tokens, Algolia search keys, Sentry DSNs.

spill only fetches the page you give it and the scripts it loads from the same
origin, so it is not a crawler and does not touch third-party CDNs.

## License

MIT
