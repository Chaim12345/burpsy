package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Vulnerable Demo Application for Testing burpsy-go
// Contains: XSS, SQLi (simulated), Missing Headers, Info Disclosure

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/api/debug", debugHandler)
	
	fmt.Println("🎯 Demo Target App running on http://localhost:8080")
	fmt.Println("   - / (Home)")
	fmt.Println("   - /search?q= (XSS Vulnerable)")
	fmt.Println("   - /login (SQLi Simulation)")
	fmt.Println("   - /api/debug (Info Disclosure)")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Vulnerability: Missing Security Headers (No CSP, X-Frame-Options, etc.)
	// Vulnerability: Server Header泄露 (Go default)
	
	html := `
	<!DOCTYPE html>
	<html>
	<head><title>Vulnerable Demo</title></head>
	<body>
		<h1>🚩 Burpsy Go Live Test Target</h1>
		<p>This app is intentionally vulnerable for testing.</p>
		<form action="/search" method="GET">
			<input type="text" name="q" placeholder="Search...">
			<button type="submit">Search</button>
		</form>
		<form action="/login" method="POST">
			<input type="text" name="user" placeholder="Username">
			<input type="password" name="pass" placeholder="Password">
			<button type="submit">Login</button>
		</form>
		<a href="/api/debug">Debug Endpoint (Don't Click)</a>
	</body>
	</html>`
	w.Write([]byte(html))
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	
	// Vulnerability: Reflected XSS (No escaping)
	// If query contains <script>, it will execute
	response := fmt.Sprintf("<h2>Results for: %s</h2>", query)
	
	w.Header().Set("Content-Type", "text/html")
	// Intentionally NOT setting X-XSS-Protection or CSP
	
	w.Write([]byte(response))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	pass := r.FormValue("pass")
	
	// Vulnerability: Simulated SQL Error based on input
	if strings.Contains(user, "'") || strings.Contains(pass, "'") {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		// Simulates a verbose SQL error message
		fmt.Fprintf(w, "SQL Error: You have an error in your SQL syntax near '%s' at line 1", user)
		return
	}
	
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Login attempted for user: %s", user)
}

func debugHandler(w http.ResponseWriter, r *http.Request) {
	// Vulnerability: Sensitive Info Disclosure
	// Exposes internal structure to unauthenticated users
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `{
		"status": "debug_mode_enabled",
		"database": "mysql://root:password@localhost:3306/prod",
		"aws_key": "AKIAIOSFODNN7EXAMPLE",
		"internal_ip": "10.0.0.5"
	}`)
}
