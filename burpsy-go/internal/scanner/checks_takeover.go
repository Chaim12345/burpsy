package scanner

// Subdomain takeover (burpsy-react-ui-0vzb.17): a host the site map has seen whose DNS CNAME points
// at a hosting service's domain, where the service says the resource behind that name is unclaimed.
// Anyone who registers the resource on that service then serves content - and receives cookies scoped
// to the parent domain - under the organisation's own hostname.
//
// Passive. The check reads the response the proxy already captured and asks the operator's DNS
// resolver two questions about the hostname: its CNAME, and (for the services whose unclaimed state is
// a dangling name) whether the CNAME target resolves. It never registers, claims or probes a resource.
//
// Evidence, all of which must hold:
//  1. the host's CNAME is the service's domain or a subdomain of it (a dot boundary, never a substring);
//  2. for a service whose unclaimed resource still answers HTTP, the captured response carries that
//     service's unclaimed-resource text (and status, where the service has a fixed one);
//  3. for a service whose unclaimed resource is a name that stops resolving, the CNAME target does not
//     resolve, on two lookups.
//
// The fingerprint table is curated from EdOverflow/can-i-take-over-xyz (fingerprints.json at
// 5bd4e128, 2026-10-12), keeping only entries marked "Vulnerable" that name the service's CNAME domain
// and carry a fingerprint specific to an unclaimed resource. Dropped, and why:
//   - marked "Edge case" or "Not vulnerable" there: GitHub Pages, Heroku, Fastly, Shopify, Netlify,
//     Vercel, Webflow, Wix, Tumblr, Intercom, Cloudfront, Google Cloud Storage, Zendesk and the rest;
//   - no CNAME domain in the list (Campaign Monitor, Canny, Cargo, Getresponse, Pingdom, Short.io,
//     Smugsmug), except two whose domain is documented by the service and added here: Pantheon
//     (pantheonsite.io) and Read the Docs (readthedocs.io);
//   - a bare HTTP status as the only fingerprint (Helprace 301, LaunchRock 500): any server can answer so;
//   - an IP address instead of a CNAME (SmartJobBoard), and DNS-delegation cases (Digital Ocean).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// IssueSubdomainTakeover is the burpsy row for a dangling CNAME to an unclaimed service resource.
const IssueSubdomainTakeover = "Subdomain takeover"

func subdomainTakeoverEnabled(c *ScanConfig) bool { return c != nil && c.CheckSubdomainTakeover }

// DNSResolver is the DNS the takeover check consults. *net.Resolver satisfies it; tests inject a fake
// through ScanConfig.DNSResolver so no fixture depends on real DNS.
type DNSResolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// takeoverService is one curated can-i-take-over-xyz entry.
type takeoverService struct {
	Service string
	// Domains are the CNAME domains the service hands out; the target must equal one or be below it.
	Domains []string
	// Match, when set, replaces the Domains test (S3's regional endpoint names).
	Match func(target string) bool
	// Fingerprint is the unclaimed-resource text (a regular expression); empty for NXDomain services.
	Fingerprint *regexp.Regexp
	// Status, when non-zero, is the status the unclaimed page is served with.
	Status int
	// NXDomain marks a service whose unclaimed resource is a CNAME target that does not resolve.
	NXDomain bool
}

func (s takeoverService) owns(target string) bool {
	if s.Match != nil {
		return s.Match(target)
	}
	for _, d := range s.Domains {
		if target == d || strings.HasSuffix(target, "."+d) {
			return true
		}
	}
	return false
}

// s3Endpoint matches the S3 endpoint names: s3.amazonaws.com, s3.<region>.amazonaws.com,
// s3-<region>.amazonaws.com, s3-website-<region>.amazonaws.com and s3-website.<region>.amazonaws.com,
// with or without the bucket as the leading labels: a resolver returns the end of the CNAME chain, and
// a bucket name's chain ends on a bare regional endpoint such as s3-1-w.amazonaws.com.
var s3Endpoint = regexp.MustCompile(`(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$`)

func fp(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }

// takeoverServices is the curated table (see the file comment for provenance and what was dropped).
var takeoverServices = []takeoverService{
	{Service: "AWS S3", Match: func(t string) bool { return s3Endpoint.MatchString(t) },
		Fingerprint: fp(`NoSuchBucket|The specified bucket does not exist`), Status: 404},
	{Service: "AWS Elastic Beanstalk", Domains: []string{"elasticbeanstalk.com"}, NXDomain: true},
	{Service: "Microsoft Azure", Domains: []string{
		"cloudapp.net", "cloudapp.azure.com", "azurewebsites.net", "blob.core.windows.net", "azure-api.net",
		"azurehdinsight.net", "azureedge.net", "azurecontainer.io", "database.windows.net",
		"azuredatalakestore.net", "search.windows.net", "azurecr.io", "redis.cache.windows.net",
		"servicebus.windows.net", "visualstudio.com"}, NXDomain: true},
	{Service: "Discourse", Domains: []string{"trydiscourse.com"}, NXDomain: true},
	{Service: "Agile CRM", Domains: []string{"agilecrm.com"}, Fingerprint: fp(`Sorry, this page is no longer available\.`)},
	{Service: "Airee.ru", Domains: []string{"airee.ru"}, Fingerprint: fp(`Ошибка 402\. Сервис Айри\.рф не оплачен`)},
	{Service: "Anima", Domains: []string{"animaapp.io"}, Fingerprint: fp(`The page you were looking for does not exist\.`)},
	{Service: "Bitbucket", Domains: []string{"bitbucket.io"}, Fingerprint: fp(`Repository not found`)},
	{Service: "Gemfury", Domains: []string{"furyns.com"}, Fingerprint: fp(`404: This page could not be found\.`)},
	{Service: "Ghost", Domains: []string{"ghost.io"}, Fingerprint: fp(`Site unavailable\.|Failed to resolve DNS path for this host`)},
	{Service: "HatenaBlog", Domains: []string{"hatenablog.com"}, Fingerprint: fp(`404 Blog is not found`)},
	{Service: "Help Juice", Domains: []string{"helpjuice.com"}, Fingerprint: fp(`We could not find what you're looking for\.`)},
	{Service: "Help Scout", Domains: []string{"helpscoutdocs.com"}, Fingerprint: fp(`No settings were found for this company:`)},
	{Service: "JetBrains YouTrack", Domains: []string{"youtrack.cloud"}, Fingerprint: fp(`is not a registered InCloud YouTrack`)},
	{Service: "Ngrok", Domains: []string{"ngrok.io"}, Fingerprint: fp(`Tunnel \S+\.ngrok\.io not found`)},
	{Service: "Pantheon", Domains: []string{"pantheonsite.io"}, Fingerprint: fp(`404 error unknown site!`)},
	{Service: "Readme.io", Domains: []string{"readme.io"}, Fingerprint: fp(`The creators of this project are still working on making everything perfect!`)},
	{Service: "Read the Docs", Domains: []string{"readthedocs.io"}, Fingerprint: fp(`The link you have followed or the URL that you entered does not exist\.`)},
	{Service: "Strikingly", Domains: []string{"s.strikinglydns.com"}, Fingerprint: fp(`PAGE NOT FOUND\.`)},
	{Service: "Surge.sh", Domains: []string{"surge.sh"}, Fingerprint: fp(`project not found`)},
	{Service: "SurveySparrow", Domains: []string{"surveysparrow.com"}, Fingerprint: fp(`Account not found\.`)},
	{Service: "Uberflip", Domains: []string{"read.uberflip.com"}, Fingerprint: fp(`The URL you've accessed does not provide a hub\.`)},
	{Service: "Uptimerobot", Domains: []string{"stats.uptimerobot.com"}, Fingerprint: fp(`page not found`)},
	{Service: "WordPress.com", Domains: []string{"wordpress.com"}, Fingerprint: fp(`Do you want to register \S*\.wordpress\.com\?`)},
	{Service: "Worksites", Domains: []string{"worksites.net"}, Fingerprint: fp(`Hello! Sorry, but the website you(&rsquo;|’|')re looking for doesn(&rsquo;|’|')t exist\.`)},
}

// TakeoverServiceFor returns the curated service whose domain the CNAME target belongs to.
func TakeoverServiceFor(target string) (takeoverService, bool) {
	t := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	for _, s := range takeoverServices {
		if s.owns(t) {
			return s, true
		}
	}
	return takeoverService{}, false
}

// takeoverHostname is the DNS name the captured exchange was addressed to. The connection target
// is used unless it is an IP literal, in which case the request's Host header names the site (a
// capture through an upstream or hosts-file override). An IP literal has no CNAME.
func takeoverHostname(cc *CheckContext) string {
	h := strings.ToLower(strings.TrimSuffix(stripPort(cc.Exchange.Host), "."))
	if net.ParseIP(h) == nil {
		return h
	}
	hh := strings.ToLower(strings.TrimSuffix(stripPort(headerValue(requestHead(cc), "host")), "."))
	if hh == "" || net.ParseIP(hh) != nil {
		return ""
	}
	return hh
}

func requestHead(cc *CheckContext) string {
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// takeoverResolver is the configured resolver, or the system one.
func takeoverResolver(c *ScanConfig) DNSResolver {
	if c != nil && c.DNSResolver != nil {
		return c.DNSResolver
	}
	return net.DefaultResolver
}

// dnsNotFound reports an authoritative "no such name / no address" answer, never a timeout or a
// server failure: a resolver that could not answer is not evidence of a dangling name.
func dnsNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound && !de.IsTimeout && !de.IsTemporary
}

// checkSubdomainTakeover is the evaluator.
func checkSubdomainTakeover(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	host := takeoverHostname(cc)
	if host == "" || !strings.Contains(host, ".") || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil, nil
	}
	r := takeoverResolver(cc.Config)
	// No cache beyond the per-host dispatch: a record the operator has just fixed must read as fixed
	// on the next scan.
	cname, err := r.LookupCNAME(ctx, host)
	if err != nil {
		return nil, nil
	}
	target := strings.ToLower(strings.TrimSuffix(cname, "."))
	if target == "" || target == host {
		return nil, nil // no CNAME: the name is the host's own
	}
	svc, ok := TakeoverServiceFor(target)
	if !ok {
		return nil, nil
	}

	var proof string
	if svc.NXDomain {
		// Two lookups, both an authoritative not-found: one failed answer is not a dangling name.
		for i := 0; i < 2; i++ {
			if _, err := r.LookupHost(ctx, target); !dnsNotFound(err) {
				return nil, nil
			}
		}
		proof = fmt.Sprintf("the CNAME target %s does not resolve (NXDOMAIN on two lookups)", target)
	} else {
		raw := responseRaw(cc.Scanner, cc.Exchange)
		if raw == "" {
			return nil, nil
		}
		status := responseStatus(raw)
		if svc.Status != 0 && status != svc.Status {
			return nil, nil
		}
		m := svc.Fingerprint.FindString(responseBody(raw))
		if m == "" {
			return nil, nil
		}
		proof = fmt.Sprintf("the response (HTTP %d) carries %s's unclaimed-resource text %q", status, svc.Service, m)
	}
	f := buildHeaderFinding(cc, IssueSubdomainTakeover, "high", "firm",
		fmt.Sprintf("%s CNAME %s (%s); %s", host, target, svc.Service, proof),
		fmt.Sprintf("%s is an alias (CNAME) of %s, a %s resource that is not claimed: whoever registers "+
			"that resource on %s serves content under %s", host, target, svc.Service, svc.Service, host))
	// One finding per hostname, however many of its URLs are audited.
	f.MergeKey = "subdomain-takeover:" + host
	return []*Finding{f}, nil
}

// hstsOrTakeover is the "Strict transport security not enforced" descriptor's runner: Burp's row under
// the passive-posture switch, and the takeover row under its own.
func hstsOrTakeover(hsts CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		var out []*Finding
		if passivePostureEnabled(cc.Config) {
			f, err := hsts(ctx, cc)
			if err != nil {
				return f, err
			}
			out = append(out, f...)
		}
		if subdomainTakeoverEnabled(cc.Config) {
			f, _ := checkSubdomainTakeover(ctx, cc)
			out = append(out, f...)
		}
		return out, nil
	}
}
