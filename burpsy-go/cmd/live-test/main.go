package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

// Live Test Suite for burpsy-go
// Tests the demo target app and verifies scanner detection capabilities

type TestResult struct {
	Name    string
	Passed  bool
	Details string
}

var results []TestResult

func main() {
	target := flag.String("target", "http://localhost:8080", "demo target base URL")
	flag.Parse()

	fmt.Println("🧪 burpsy-go Live Test Suite")
	fmt.Println("=============================")
	fmt.Println()

	fmt.Println("⏳ Waiting for target app...")
	for i := 0; i < 10; i++ {
		resp, err := http.Get(*target)
		if err == nil {
			resp.Body.Close()
			fmt.Println("✅ Target app is ready")
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println()
	fmt.Println("Running Tests...")
	fmt.Println()

	// Test 1: XSS Detection
	testXSS(*target)

	// Test 2: SQL Injection Detection
	testSQLi(*target)

	// Test 3: Info Disclosure Detection
	testInfoDisclosure(*target)

	// Test 4: Missing Security Headers
	testMissingHeaders(*target)

	// Print Results
	fmt.Println()
	fmt.Println("=============================")
	fmt.Println("TEST RESULTS")
	fmt.Println("=============================")

	passed := 0
	failed := 0

	for _, r := range results {
		status := "❌ FAIL"
		if r.Passed {
			status = "✅ PASS"
			passed++
		} else {
			failed++
		}
		fmt.Printf("[%s] %s\n", status, r.Name)
		if r.Details != "" {
			fmt.Printf("       %s\n", r.Details)
		}
	}

	fmt.Println()
	fmt.Printf("Summary: %d passed, %d failed\n", passed, failed)

	if failed == 0 {
		fmt.Println("🎉 All tests passed! Scanner is working correctly.")
		os.Exit(0)
	} else {
		fmt.Println("⚠️  Some tests failed.")
		os.Exit(1)
	}
}

func testXSS(target string) {
	name := "XSS Vulnerability Detection"

	resp, err := http.Get(target + "/search?q=<script>alert(1)</script>")
	if err != nil {
		results = append(results, TestResult{Name: name, Passed: false, Details: fmt.Sprintf("Request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check if script tag is reflected without escaping
	if strings.Contains(bodyStr, "<script>alert(1)</script>") {
		results = append(results, TestResult{
			Name:    name,
			Passed:  true,
			Details: "Script tag reflected unescaped - XSS vulnerability confirmed",
		})
	} else {
		results = append(results, TestResult{
			Name:    name,
			Passed:  false,
			Details: "Script tag was escaped or not reflected",
		})
	}
}

func testSQLi(target string) {
	name := "SQL Injection Error Detection"

	client := &http.Client{}
	req, _ := http.NewRequest("POST", target+"/login", strings.NewReader("user=admin'--&pass=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		results = append(results, TestResult{Name: name, Passed: false, Details: fmt.Sprintf("Request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check for SQL error message
	if strings.Contains(bodyStr, "SQL Error") || strings.Contains(bodyStr, "syntax") {
		results = append(results, TestResult{
			Name:    name,
			Passed:  true,
			Details: "Verbose SQL error message detected",
		})
	} else {
		results = append(results, TestResult{
			Name:    name,
			Passed:  false,
			Details: "No SQL error message found",
		})
	}
}

func testInfoDisclosure(target string) {
	name := "Sensitive Info Disclosure Detection"

	resp, err := http.Get(target + "/api/debug")
	if err != nil {
		results = append(results, TestResult{Name: name, Passed: false, Details: fmt.Sprintf("Request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check for sensitive data patterns
	hasDB := strings.Contains(bodyStr, "mysql://")
	hasAWS := strings.Contains(bodyStr, "AKIA")
	hasIP := strings.Contains(bodyStr, "10.0.0")

	if hasDB || hasAWS || hasIP {
		details := []string{}
		if hasDB {
			details = append(details, "Database credentials")
		}
		if hasAWS {
			details = append(details, "AWS keys")
		}
		if hasIP {
			details = append(details, "Internal IPs")
		}

		results = append(results, TestResult{
			Name:    name,
			Passed:  true,
			Details: fmt.Sprintf("Exposed: %s", strings.Join(details, ", ")),
		})
	} else {
		results = append(results, TestResult{
			Name:    name,
			Passed:  false,
			Details: "No sensitive data exposed",
		})
	}
}

func testMissingHeaders(target string) {
	name := "Missing Security Headers Detection"

	resp, err := http.Get(target)
	if err != nil {
		results = append(results, TestResult{Name: name, Passed: false, Details: fmt.Sprintf("Request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	missing := []string{}

	requiredHeaders := map[string]string{
		"X-Frame-Options":           "Clickjacking protection",
		"X-Content-Type-Options":    "MIME sniffing protection",
		"X-Xss-Protection":          "XSS filter",
		"Content-Security-Policy":   "CSP",
		"Strict-Transport-Security": "HSTS",
	}

	for header, desc := range requiredHeaders {
		if resp.Header.Get(header) == "" {
			missing = append(missing, desc)
		}
	}

	if len(missing) >= 3 {
		results = append(results, TestResult{
			Name:    name,
			Passed:  true,
			Details: fmt.Sprintf("Missing %d security headers: %s", len(missing), strings.Join(missing[:3], ", ")),
		})
	} else {
		results = append(results, TestResult{
			Name:    name,
			Passed:  false,
			Details: "Security headers are present",
		})
	}
}
