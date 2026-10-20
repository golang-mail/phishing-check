// phishing-check scores emails for phishing indicators using header + URL +
// body heuristics. Verdict is matched=true when score >= threshold; optional
// actions (flag, move) are attached so filters can react without extra config.
//
// This is NOT a replacement for SpamAssassin / rspamd — it's a quick local
// signal for the most common consumer-phishing patterns: domain spoofing,
// auth failures, urgent body language, and link/text mismatches.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type envelope struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type initRequest struct {
	HostVersion string          `json:"host_version"`
	Config      json.RawMessage `json:"config,omitempty"`
}

type pluginAction struct {
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

type pluginConfig struct {
	// Threshold: emails scoring >= this match.
	Threshold int `yaml:"threshold" json:"threshold"`
	// ActionsOnMatch are attached to the verdict on match.
	ActionsOnMatch []pluginAction `yaml:"actions_on_match" json:"actions_on_match"`
	// BrandDomains maps display-name keywords → expected From hostname suffix.
	// e.g. "paypal" → "paypal.com" means "if From display name contains
	// 'paypal' but the email isn't from *.paypal.com, that's spoofing."
	BrandDomains map[string]string `yaml:"brand_domains" json:"brand_domains"`
	Verbose      bool              `yaml:"verbose" json:"verbose"`
}

type address struct {
	PersonalName string `json:"PersonalName"`
	MailboxName  string `json:"MailboxName"`
	HostName     string `json:"HostName"`
}

type emailEnvelope struct {
	Date    time.Time  `json:"Date"`
	Subject string     `json:"Subject"`
	From    []*address `json:"From"`
	To      []*address `json:"To"`
	Cc      []*address `json:"Cc"`
}

type evalReq struct {
	Email struct {
		UID         uint32            `json:"uid"`
		Account     string            `json:"account"`
		Mailbox     string            `json:"mailbox"`
		Envelope    *emailEnvelope    `json:"envelope"`
		Headers     map[string]string `json:"headers"`
		Body        string            `json:"body"`
		ContentType string            `json:"content_type"`
	} `json:"email"`
	FilterConfig string `json:"filter_config"`
}

var cfg pluginConfig

// defaultBrands seeds BrandDomains when the user hasn't configured any.
// Keep this list short — false positives on brand-spoofing are damaging.
var defaultBrands = map[string]string{
	"paypal":      "paypal.com",
	"amazon":      "amazon.com",
	"apple":       "apple.com",
	"microsoft":   "microsoft.com",
	"google":      "google.com",
	"netflix":     "netflix.com",
	"facebook":    "facebook.com",
	"chase":       "chase.com",
	"wells fargo": "wellsfargo.com",
}

// urlShorteners hide the real destination — that's a phishing red flag in
// unsolicited mail. Legit bulk senders sometimes use them too, so this is +1
// not a kill signal.
var urlShorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true,
	"ow.ly": true, "is.gd": true, "buff.ly": true, "rebrand.ly": true,
	"shorturl.at": true, "tiny.cc": true,
}

// suspiciousTLDs are statistically over-represented in phishing campaigns.
// +1 signal — legit mail does land here, just rarely.
var suspiciousTLDs = map[string]bool{
	"zip": true, "mov": true, "xyz": true, "top": true, "click": true,
	"link": true, "country": true, "stream": true, "gdn": true, "racing": true,
	"tk": true, "ml": true, "ga": true, "cf": true,
}

func main() {
	log.SetFlags(0)
	path := os.Getenv("GO_MAIL_PLUGIN_SOCKET")
	if path == "" {
		log.Fatal("GO_MAIL_PLUGIN_SOCKET not set")
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalf("listen %s: %v", path, err)
	}
	_ = os.Chmod(path, 0o600)
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go serve(conn)
	}
}

func serve(conn net.Conn) {
	defer conn.Close()
	in := bufio.NewScanner(conn)
	in.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	out := json.NewEncoder(conn)

	for in.Scan() {
		var msg envelope
		if err := json.Unmarshal(in.Bytes(), &msg); err != nil {
			log.Printf("bad envelope: %v", err)
			continue
		}
		switch msg.Method {
		case "init":
			handleInit(out, msg)
		case "evaluate":
			handleEvaluate(out, msg)
		case "shutdown":
			return
		}
	}
}

func handleInit(out *json.Encoder, msg envelope) {
	cfg.Threshold = 4
	var req initRequest
	_ = json.Unmarshal(msg.Payload, &req)
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			log.Printf("decode plugin config: %v", err)
		}
	}
	if cfg.BrandDomains == nil {
		cfg.BrandDomains = defaultBrands
	}
	manifest, _ := json.Marshal(map[string]any{
		"name":      "phishing-check",
		"version":   "0.1.0",
		"actions":   []string{"flag", "move", "mark_as_spam"},
		"wants":     []string{"envelope", "headers", "body"},
		"cacheable": true,
	})
	_ = out.Encode(envelope{
		ID:      msg.ID,
		Type:    "response",
		Method:  "init",
		Payload: manifest,
	})
	log.Printf("initialized: threshold=%d brands=%d", cfg.Threshold, len(cfg.BrandDomains))
}

func handleEvaluate(out *json.Encoder, msg envelope) {
	var r evalReq
	if err := json.Unmarshal(msg.Payload, &r); err != nil {
		respond(out, msg.ID, map[string]any{"error": "decode evaluate: " + err.Error()})
		return
	}

	score, reasons := scorePhishing(&r)
	matched := score >= cfg.Threshold
	if cfg.Verbose {
		log.Printf("uid=%d acct=%s/%s subject=%q score=%d matched=%v reasons=%s",
			r.Email.UID, r.Email.Account, r.Email.Mailbox,
			truncate(envelopeSubject(r.Email.Envelope), 60), score, matched, strings.Join(reasons, ","))
	}

	resp := map[string]any{
		"matched": matched,
		"reason":  fmt.Sprintf("score=%d %s", score, strings.Join(reasons, ",")),
	}
	if matched && len(cfg.ActionsOnMatch) > 0 {
		resp["actions"] = cfg.ActionsOnMatch
	}
	respond(out, msg.ID, resp)
}

func scorePhishing(r *evalReq) (int, []string) {
	score := 0
	var reasons []string
	add := func(n int, reason string) {
		score += n
		reasons = append(reasons, fmt.Sprintf("%s+%d", reason, n))
	}

	get := func(name string) string {
		for k, v := range r.Email.Headers {
			if strings.EqualFold(k, name) {
				return v
			}
		}
		return ""
	}

	// 1. Authentication-Results: look for fail/softfail in SPF, DKIM, DMARC.
	authRes := strings.ToLower(get("Authentication-Results"))
	if authRes != "" {
		if strings.Contains(authRes, "spf=fail") || strings.Contains(authRes, "spf=softfail") {
			add(2, "spf-fail")
		}
		if strings.Contains(authRes, "dkim=fail") {
			add(2, "dkim-fail")
		}
		if strings.Contains(authRes, "dmarc=fail") {
			add(3, "dmarc-fail")
		}
	}

	// 2. From-domain analysis.
	var fromHost, fromDisplay string
	if r.Email.Envelope != nil && len(r.Email.Envelope.From) > 0 {
		fromHost = strings.ToLower(r.Email.Envelope.From[0].HostName)
		fromDisplay = strings.ToLower(r.Email.Envelope.From[0].PersonalName)
	}

	// 2a. Display-name brand spoofing.
	for keyword, expected := range cfg.BrandDomains {
		if strings.Contains(fromDisplay, strings.ToLower(keyword)) {
			if !domainMatches(fromHost, expected) {
				add(4, "brand-spoof-"+keyword)
				break // one brand-spoof signal is enough
			}
		}
	}

	// 2b. Reply-To on a different domain than From.
	replyTo := get("Reply-To")
	if replyTo != "" && fromHost != "" {
		rh := extractDomain(replyTo)
		if rh != "" && !sharesRegisteredDomain(rh, fromHost) {
			add(2, "replyto-mismatch")
		}
	}

	// 2c. From-host on a suspicious TLD.
	if fromHost != "" {
		tld := tldOf(fromHost)
		if suspiciousTLDs[tld] {
			add(1, "from-tld-"+tld)
		}
	}

	// 3. URLs in body.
	urls := extractURLs(r.Email.Body)
	if len(urls) > 0 {
		ipURLs := 0
		shortenerURLs := 0
		suspiciousTLDURLs := 0
		punycodeURLs := 0
		for _, u := range urls {
			h := strings.ToLower(u.Host)
			if h == "" {
				continue
			}
			// Strip port if present.
			if i := strings.Index(h, ":"); i >= 0 {
				h = h[:i]
			}
			if net.ParseIP(h) != nil {
				ipURLs++
				continue
			}
			if urlShorteners[h] {
				shortenerURLs++
			}
			if suspiciousTLDs[tldOf(h)] {
				suspiciousTLDURLs++
			}
			if strings.Contains(h, "xn--") {
				punycodeURLs++
			}
		}
		if ipURLs > 0 {
			add(3, fmt.Sprintf("raw-ip-urls(%d)", ipURLs))
		}
		if shortenerURLs > 0 {
			add(1, fmt.Sprintf("shortener-urls(%d)", shortenerURLs))
		}
		if suspiciousTLDURLs > 0 {
			add(1, fmt.Sprintf("susp-tld-urls(%d)", suspiciousTLDURLs))
		}
		if punycodeURLs > 0 {
			add(2, fmt.Sprintf("punycode-urls(%d)", punycodeURLs))
		}

		// 3b. Link/text mismatch in HTML: <a href="evil.com">paypal.com</a>.
		if mismatches := findHrefTextMismatches(r.Email.Body); mismatches > 0 {
			add(3, fmt.Sprintf("href-text-mismatch(%d)", mismatches))
		}

		// 3c. <form> action submitting off-domain.
		if formActionSuspicious(r.Email.Body, fromHost) {
			add(3, "html-form")
		}
	}

	// 4. Body urgency phrases.
	if r.Email.Body != "" {
		body := strings.ToLower(r.Email.Body)
		urgencyHits := 0
		for _, phrase := range []string{
			"verify your account", "verify your identity", "confirm your account",
			"account will be suspended", "account has been suspended",
			"unusual activity", "suspicious activity", "unauthorized access",
			"click here immediately", "act now", "limited time",
			"update your payment", "billing problem", "tax refund",
		} {
			if strings.Contains(body, phrase) {
				urgencyHits++
			}
		}
		if urgencyHits >= 2 {
			add(2, fmt.Sprintf("urgency(%d)", urgencyHits))
		} else if urgencyHits == 1 {
			add(1, "urgency(1)")
		}
	}

	return score, reasons
}

// domainMatches checks whether host equals expected or is a subdomain of it.
func domainMatches(host, expected string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	expected = strings.ToLower(strings.TrimSpace(expected))
	if host == "" || expected == "" {
		return false
	}
	return host == expected || strings.HasSuffix(host, "."+expected)
}

// sharesRegisteredDomain compares the last two labels of two hostnames.
// Naive — doesn't handle eTLDs like co.uk — but good enough for Reply-To check.
func sharesRegisteredDomain(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	la := lastTwoLabels(a)
	lb := lastTwoLabels(b)
	return la != "" && la == lb
}

func lastTwoLabels(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func tldOf(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func extractDomain(addr string) string {
	// Reply-To may be "Name <user@host>" or just "user@host".
	if i := strings.LastIndex(addr, "<"); i >= 0 {
		if j := strings.Index(addr[i:], ">"); j >= 0 {
			addr = addr[i+1 : i+j]
		}
	}
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return strings.ToLower(strings.TrimSpace(addr[i+1:]))
	}
	return ""
}

var urlRE = regexp.MustCompile(`https?://[^\s<>()\[\]"'\\]+`)

func extractURLs(body string) []*url.URL {
	if body == "" {
		return nil
	}
	matches := urlRE.FindAllString(body, -1)
	out := make([]*url.URL, 0, len(matches))
	for _, m := range matches {
		// Strip trailing punctuation that's almost never part of a URL.
		m = strings.TrimRight(m, ".,;:!?)]")
		u, err := url.Parse(m)
		if err == nil && u.Host != "" {
			out = append(out, u)
		}
	}
	return out
}

// findHrefTextMismatches counts <a href="X">Y</a> where Y itself looks like a
// URL or hostname pointing somewhere different from X. This is the classic
// phishing pattern: text says "paypal.com" but href goes to evil.example.
var anchorRE = regexp.MustCompile(`(?is)<a\s[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</\s*a\s*>`)
var hostInTextRE = regexp.MustCompile(`(?i)\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b`)

func findHrefTextMismatches(body string) int {
	matches := anchorRE.FindAllStringSubmatch(body, -1)
	count := 0
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		hrefURL := strings.TrimSpace(m[1])
		text := stripTags(m[2])
		// Skip if href isn't http(s) — mailto:, tel:, etc. aren't phishing-relevant.
		if !strings.HasPrefix(strings.ToLower(hrefURL), "http") {
			continue
		}
		hu, err := url.Parse(hrefURL)
		if err != nil || hu.Host == "" {
			continue
		}
		hrefHost := strings.ToLower(hu.Host)
		// Look for anything that looks like a hostname inside the visible text.
		for _, hm := range hostInTextRE.FindAllStringSubmatch(text, -1) {
			textHost := strings.ToLower(hm[1])
			// Ignore matches without a dot (false positives like "click.here") — already filtered by regex.
			// Ignore cases where the text host is contained in or matches the real host.
			if strings.Contains(hrefHost, textHost) || strings.Contains(textHost, hrefHost) {
				continue
			}
			// Both look like real domains — text says one, href goes to another.
			if !sharesRegisteredDomain(hrefHost, textHost) {
				count++
				break
			}
		}
	}
	return count
}

var formRE = regexp.MustCompile(`(?is)<form[^>]*\baction\s*=\s*["']([^"']+)["']`)
var tagStripRE = regexp.MustCompile(`<[^>]+>`)

func stripTags(s string) string {
	return tagStripRE.ReplaceAllString(s, "")
}

// formActionSuspicious returns true if the body contains a <form> whose action
// posts to an http(s) URL that isn't on the From domain. Most legit mail has
// no forms at all; mail clients render them but submission rarely works in
// practice — phishers use them anyway because some clients still try.
func formActionSuspicious(body, fromHost string) bool {
	for _, m := range formRE.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		action := strings.TrimSpace(m[1])
		if !strings.HasPrefix(strings.ToLower(action), "http") {
			continue
		}
		u, err := url.Parse(action)
		if err != nil || u.Host == "" {
			continue
		}
		if fromHost != "" && sharesRegisteredDomain(u.Host, fromHost) {
			continue
		}
		return true
	}
	return false
}

func envelopeSubject(e *emailEnvelope) string {
	if e == nil {
		return ""
	}
	return e.Subject
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func respond(out *json.Encoder, id string, payload any) {
	raw, _ := json.Marshal(payload)
	_ = out.Encode(envelope{
		ID:      id,
		Type:    "response",
		Method:  "evaluate",
		Payload: raw,
	})
}
