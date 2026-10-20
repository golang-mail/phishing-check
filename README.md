# phishing-check

Heuristic phishing scorer. Looks at SPF/DKIM/DMARC results, From-domain spoofing, link/text mismatches, suspicious URLs, and urgency phrasing. Returns `matched: true` when the score crosses a threshold; can attach `flag` / `move` actions.

**This is not a replacement for a real spam engine** like rspamd or SpamAssassin. It's a lightweight local check for the specific patterns that target consumers in the inbox: brand spoofing, link mismatch, fake "urgent" account-action mail.

## Install

```bash
go install github.com/golang-mail/phishing-check@latest
```

## What it scores

| Signal | Points |
|---|---|
| `Authentication-Results: dmarc=fail` | +3 |
| `spf=fail`/`softfail` or `dkim=fail` | +2 each |
| Display name matches a known brand but From host doesn't (e.g. "PayPal" but not from `*.paypal.com`) | +4 |
| Reply-To on a different registered domain than From | +2 |
| Body contains URLs to raw IP addresses | +3 |
| `<a href="X">Y</a>` where the visible text Y is a different host than X | +3 per occurrence |
| `<form action=...>` posting off the From domain | +3 |
| URLs to punycode (`xn--`) hosts | +2 |
| URLs through known shorteners (bit.ly, t.co, …) | +1 |
| URLs to or From-host on a suspicious TLD (`.zip`, `.xyz`, `.tk`, …) | +1 |
| Two or more urgency phrases ("verify your account", "suspended", "act now") | +2 |
| One urgency phrase | +1 |

Default threshold is **4** — high enough that no single weak signal triggers, but auth-fail combined with one URL signal is enough.

## Register

```yaml
plugins:
  - name: phishing-check
    command: ["/path/to/phishing-check"]
    transport: socket   # default; the plugin listens on $GO_MAIL_PLUGIN_SOCKET
    timeout: 5s
    config:
      threshold: 4
      verbose: false
      actions_on_match:
        - type: flag
          value: "$Phishing"
        # optional:
        # - type: move
        #   value: "Spam"
      brand_domains:
        # display-name keyword → expected From hostname suffix
        paypal: "paypal.com"
        amazon: "amazon.com"
        # ... defaults include paypal/amazon/apple/microsoft/google/netflix/facebook/chase
```

If `brand_domains` is omitted the plugin uses its built-in list. Override only when you need to add/remove brands or tighten matching.

## Use it from filters

```yaml
filters:
  - name: catch-phishing
    mailboxes: ["INBOX"]
    conditions:
      - field: plugin:phishing-check
        operator: matches
        value: ""
    actions: []   # actions come from actions_on_match
```

Or drive actions from the filter:

```yaml
filters:
  - name: catch-phishing
    mailboxes: ["INBOX"]
    conditions:
      - field: plugin:phishing-check
        operator: matches
        value: ""
    actions:
      - type: flag
        value: "$Phishing"
      - type: move
        value: "Spam"
```

## Tuning

Run with `verbose: true` and look at the `reason` field in the plugin's logs (e.g. `score=5 dmarc-fail+3,brand-spoof-paypal+4`). False positives most commonly come from:

- **Legit transactional mail through ESPs** that show DKIM-fail because of forwarding — pair this plugin with a `from` allow-list filter that runs first.
- **Auto-generated verification mail** that uses urgency language. Lower urgency weight by setting a higher `threshold`.

The host caches verdicts per `(uid, plugin_version, filter_config)`, so re-evaluation is free until you change config.
