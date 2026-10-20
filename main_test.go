package main

import (
	"strings"
	"testing"
)

func phishReq(headers map[string]string, body, ct string, from *address) *evalReq {
	r := &evalReq{}
	r.Email.Headers = headers
	r.Email.Body = body
	r.Email.ContentType = ct
	if from != nil {
		r.Email.Envelope = &emailEnvelope{From: []*address{from}}
	}
	return r
}

func TestDomainMatches(t *testing.T) {
	cases := []struct {
		host, expected string
		want           bool
	}{
		{"paypal.com", "paypal.com", true},
		{"mail.paypal.com", "paypal.com", true},
		{"PayPal.com", "paypal.com", true},
		{"paypa1.com", "paypal.com", false},
		{"paypal.com.evil.com", "paypal.com", false},
		{"", "paypal.com", false},
		{"paypal.com", "", false},
	}
	for _, c := range cases {
		if got := domainMatches(c.host, c.expected); got != c.want {
			t.Errorf("domainMatches(%q, %q) = %v, want %v", c.host, c.expected, got, c.want)
		}
	}
}

func TestSharesRegisteredDomain(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"mail.example.com", "smtp.example.com", true},
		{"example.com", "example.com", true},
		{"example.com", "evil.com", false},
		{"a.b.example.com", "x.y.example.com", true},
		// Naive impl will get this "wrong" — treats co.uk as the registered domain.
		// Documented limitation; we don't fix it because URL extraction is already
		// downstream of strong signals like DMARC fail.
		{"foo.co.uk", "bar.co.uk", true},
	}
	for _, c := range cases {
		if got := sharesRegisteredDomain(c.a, c.b); got != c.want {
			t.Errorf("sharesRegisteredDomain(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestExtractDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"user@example.com", "example.com"},
		{"Name <user@example.com>", "example.com"},
		{"  Spaces <u@example.com>  ", "example.com"},
		{"plainnote", ""},
		{"User@SUB.Example.COM", "sub.example.com"},
	}
	for _, c := range cases {
		if got := extractDomain(c.in); got != c.want {
			t.Errorf("extractDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFindHrefTextMismatches(t *testing.T) {
	body := `
Click <a href="https://evil.example/login">paypal.com</a> to verify.
And <a href="https://paypal.com/login">paypal.com</a> here.
And <a href="https://help.example.com/x">click here</a> normal.
`
	got := findHrefTextMismatches(body)
	if got != 1 {
		t.Errorf("findHrefTextMismatches() = %d, want 1 (only the first link is a real mismatch)", got)
	}
}

func TestFindHrefTextMismatches_NestedTags(t *testing.T) {
	// Visible text inside <span>/<b> should still be checked against the href.
	body := `<a href="https://evil.example/x"><span style="color:#0070ba">paypal.com</span></a>`
	got := findHrefTextMismatches(body)
	if got != 1 {
		t.Errorf("got %d, want 1 (text inside nested tags should still be inspected)", got)
	}
}

func TestFormActionSuspicious(t *testing.T) {
	cases := []struct {
		body     string
		fromHost string
		want     bool
	}{
		{`<form action="https://evil.example/submit">`, "real.example.com", true},
		{`<form action="https://real.example.com/submit">`, "mail.real.example.com", false},
		{`<form action="mailto:a@b.com">`, "mail.example.com", false}, // non-http actions ignored
		{`no form here`, "example.com", false},
	}
	for i, c := range cases {
		if got := formActionSuspicious(c.body, c.fromHost); got != c.want {
			t.Errorf("case %d: formActionSuspicious() = %v, want %v", i, got, c.want)
		}
	}
}

func TestExtractURLs(t *testing.T) {
	body := `Visit https://example.com/path and http://other.example/x?y=1.
Trailing punctuation https://foo.com/path. should drop the period.
Fragment https://example.com/page#section is intact.`
	urls := extractURLs(body)
	if len(urls) != 4 {
		t.Fatalf("got %d urls, want 4: %v", len(urls), urls)
	}
	if urls[2].Host != "foo.com" || strings.HasSuffix(urls[2].Path, ".") {
		t.Errorf("trailing period not stripped: %q", urls[2].String())
	}
}

func TestScorePhishing_AuthFailures(t *testing.T) {
	cfg = pluginConfig{Threshold: 4, BrandDomains: defaultBrands}
	r := phishReq(map[string]string{
		"Authentication-Results": "spf=fail (sender ip not allowed) dkim=fail dmarc=fail",
	}, "", "", &address{MailboxName: "x", HostName: "example.com"})
	score, reasons := scorePhishing(r)
	if score < 7 { // 2 + 2 + 3
		t.Errorf("score=%d, want >= 7. reasons=%v", score, reasons)
	}
}

func TestScorePhishing_BrandSpoof(t *testing.T) {
	cfg = pluginConfig{Threshold: 4, BrandDomains: defaultBrands}
	// "PayPal" in display name but mail comes from sketchy.tk
	r := phishReq(nil, "", "", &address{
		PersonalName: "PayPal Service",
		MailboxName:  "service",
		HostName:     "sketchy.tk",
	})
	score, reasons := scorePhishing(r)
	if score < 4 {
		t.Errorf("score=%d, want >= 4 (brand spoof). reasons=%v", score, reasons)
	}

	// Real PayPal: same display name, real domain — no brand-spoof signal.
	r2 := phishReq(nil, "", "", &address{
		PersonalName: "PayPal",
		MailboxName:  "service",
		HostName:     "paypal.com",
	})
	score2, reasons2 := scorePhishing(r2)
	for _, reason := range reasons2 {
		if strings.Contains(reason, "brand-spoof") {
			t.Errorf("real paypal.com should not trigger brand-spoof. reasons=%v", reasons2)
			break
		}
	}
	// Suspicious-tld signal also shouldn't fire on .com
	if score2 != 0 {
		t.Errorf("score=%d for legit paypal.com, want 0. reasons=%v", score2, reasons2)
	}
}

func TestScorePhishing_HrefTextMismatch(t *testing.T) {
	cfg = pluginConfig{Threshold: 4, BrandDomains: defaultBrands}
	body := `<a href="https://evil.example/login">paypal.com</a>`
	r := phishReq(nil, body, "text/html",
		&address{MailboxName: "x", HostName: "evil.example"})
	score, reasons := scorePhishing(r)
	// +3 for href-text-mismatch
	if score < 3 {
		t.Errorf("score=%d, want >= 3. reasons=%v", score, reasons)
	}
}

func TestScorePhishing_RawIP(t *testing.T) {
	cfg = pluginConfig{Threshold: 4, BrandDomains: defaultBrands}
	body := `Click http://192.0.2.55/login`
	r := phishReq(nil, body, "text/plain",
		&address{MailboxName: "x", HostName: "example.com"})
	score, _ := scorePhishing(r)
	if score < 3 {
		t.Errorf("score=%d, want >= 3 for raw-IP URL", score)
	}
}

func TestScorePhishing_ReplyToMismatch(t *testing.T) {
	cfg = pluginConfig{Threshold: 4, BrandDomains: defaultBrands}
	r := phishReq(map[string]string{
		"Reply-To": "Attacker <pwn@evil.example>",
	}, "", "", &address{MailboxName: "support", HostName: "example.com"})
	score, reasons := scorePhishing(r)
	if score < 2 {
		t.Errorf("score=%d, want >= 2. reasons=%v", score, reasons)
	}
}

func TestScorePhishing_UrgencyAlone(t *testing.T) {
	cfg = pluginConfig{Threshold: 4, BrandDomains: defaultBrands}
	body := `Your account will be suspended due to unusual activity. Verify your account now.`
	r := phishReq(nil, body, "text/plain",
		&address{MailboxName: "x", HostName: "example.com"})
	score, reasons := scorePhishing(r)
	// Three urgency phrases → +2 (single bucket of 2 since >= 2 hits)
	if score != 2 {
		t.Errorf("score=%d, want 2 (urgency only). reasons=%v", score, reasons)
	}
}

func TestScorePhishing_LegitMail(t *testing.T) {
	cfg = pluginConfig{Threshold: 4, BrandDomains: defaultBrands}
	body := `Hi! Thanks for your order. https://shop.example.com/order/123`
	r := phishReq(map[string]string{
		"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
	}, body, "text/plain", &address{
		PersonalName: "Shop",
		MailboxName:  "noreply",
		HostName:     "shop.example.com",
	})
	score, reasons := scorePhishing(r)
	if score != 0 {
		t.Errorf("score=%d, want 0 for legit mail. reasons=%v", score, reasons)
	}
}
