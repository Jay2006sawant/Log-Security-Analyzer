package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"gopkg.in/yaml.v2"
)

// LogEntry represents a parsed log entry
type LogEntry struct {
	Timestamp string `json:"timestamp" yaml:"timestamp"`
	Level     string `json:"level" yaml:"level"`
	Message   string `json:"message" yaml:"message"`
	IP        string `json:"ip,omitempty" yaml:"ip,omitempty"`
	User      string `json:"user,omitempty" yaml:"user,omitempty"`
	Status    int    `json:"status,omitempty" yaml:"status,omitempty"`
}

// SecurityAlert represents a security concern found in logs
type SecurityAlert struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	LogEntry    string `json:"log_entry"`
	Timestamp   string `json:"timestamp"`
}

// LogAnalyzer handles log analysis functionality
type LogAnalyzer struct {
	alerts []SecurityAlert
}

func main() {
	fmt.Println("🔍 Log Security Analyzer v1.0")
	fmt.Println("================================")
	
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <command> [options]")
		fmt.Println("Commands:")
		fmt.Println("  analyze <logfile>  - Analyze log file for security patterns")
		fmt.Println("  server            - Start web interface for log analysis")
		fmt.Println("  demo              - Generate sample logs and analyze them")
		return
	}

	command := os.Args[1]
	analyzer := &LogAnalyzer{}

	switch command {
	case "analyze":
		if len(os.Args) < 3 {
			fmt.Println("Please provide a log file to analyze")
			return
		}
		analyzer.analyzeLogFile(os.Args[2])
	case "server":
		analyzer.startWebServer()
	case "demo":
		analyzer.runDemo()
	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}

func (la *LogAnalyzer) analyzeLogFile(filename string) {
	fmt.Printf("📂 Analyzing log file: %s\n", filename)
	
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		la.analyzeLine(line, lineNumber)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	la.printResults()
}

func (la *LogAnalyzer) analyzeLine(line string, lineNumber int) {
	// Try to parse as JSON first (vulnerable YAML parsing will be demonstrated)
	var entry LogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		// Try YAML parsing (this uses the vulnerable gopkg.in/yaml.v2)
		if err := yaml.Unmarshal([]byte(line), &entry); err != nil {
			// Treat as plain text log
			entry = LogEntry{
				Timestamp: time.Now().Format(time.RFC3339),
				Message:   line,
			}
		}
	}

	// Security pattern detection
	la.detectSecurityPatterns(entry, line, lineNumber)
}

func (la *LogAnalyzer) detectSecurityPatterns(entry LogEntry, originalLine string, lineNumber int) {
	line := strings.ToLower(originalLine)
	
	// Failed login attempts
	if matched, _ := regexp.MatchString(`(failed login|authentication failed|invalid credentials|login failed)`, line); matched {
		la.alerts = append(la.alerts, SecurityAlert{
			Type:        "Failed Authentication",
			Severity:    "MEDIUM",
			Description: "Potential brute force attack or credential stuffing",
			LogEntry:    originalLine,
			Timestamp:   entry.Timestamp,
		})
	}

	// SQL Injection patterns
	if matched, _ := regexp.MatchString(`(union select|drop table|insert into|delete from|' or 1=1)`, line); matched {
		la.alerts = append(la.alerts, SecurityAlert{
			Type:        "SQL Injection Attempt",
			Severity:    "HIGH",
			Description: "Potential SQL injection attack detected",
			LogEntry:    originalLine,
			Timestamp:   entry.Timestamp,
		})
	}

	// XSS patterns
	if matched, _ := regexp.MatchString(`(<script|javascript:|onload=|onerror=)`, line); matched {
		la.alerts = append(la.alerts, SecurityAlert{
			Type:        "XSS Attempt",
			Severity:    "HIGH",
			Description: "Potential Cross-Site Scripting attack",
			LogEntry:    originalLine,
			Timestamp:   entry.Timestamp,
		})
	}

	// Suspicious file access
	if matched, _ := regexp.MatchString(`(\.\./|/etc/passwd|/etc/shadow|\.\.\\)`, line); matched {
		la.alerts = append(la.alerts, SecurityAlert{
			Type:        "Directory Traversal",
			Severity:    "HIGH",
			Description: "Potential directory traversal attack",
			LogEntry:    originalLine,
			Timestamp:   entry.Timestamp,
		})
	}

	// Rate limiting triggers
	if matched, _ := regexp.MatchString(`(rate limit|too many requests|429)`, line); matched {
		la.alerts = append(la.alerts, SecurityAlert{
			Type:        "Rate Limiting",
			Severity:    "MEDIUM",
			Description: "Rate limiting triggered - possible DoS attempt",
			LogEntry:    originalLine,
			Timestamp:   entry.Timestamp,
		})
	}
}

func (la *LogAnalyzer) printResults() {
	fmt.Printf("\n📊 Analysis Results\n")
	fmt.Printf("==================\n")
	fmt.Printf("Total alerts found: %d\n\n", len(la.alerts))

	if len(la.alerts) == 0 {
		fmt.Println("✅ No security concerns detected!")
		return
	}

	// Group by severity
	high, medium, low := 0, 0, 0
	for _, alert := range la.alerts {
		switch alert.Severity {
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}

	fmt.Printf("🔴 High Severity: %d\n", high)
	fmt.Printf("🟡 Medium Severity: %d\n", medium)
	fmt.Printf("🟢 Low Severity: %d\n\n", low)

	// Print detailed alerts
	fmt.Println("Detailed Alerts:")
	fmt.Println("----------------")
	for i, alert := range la.alerts {
		fmt.Printf("%d. [%s] %s\n", i+1, alert.Severity, alert.Type)
		fmt.Printf("   Description: %s\n", alert.Description)
		fmt.Printf("   Log Entry: %s\n", alert.LogEntry)
		if alert.Timestamp != "" {
			fmt.Printf("   Timestamp: %s\n", alert.Timestamp)
		}
		fmt.Println()
	}
}

func (la *LogAnalyzer) startWebServer() {
	fmt.Println("🌐 Starting web server on :8080")
	fmt.Println("Visit http://localhost:8080 for web interface")
	
	// Using vulnerable chi router (v4.1.2 has known issues)
	r := chi.NewRouter()
	
	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	
	// Routes
	r.Get("/", la.webHome)
	r.Post("/analyze", la.webAnalyze)
	r.Get("/health", la.webHealth)
	
	log.Fatal(http.ListenAndServe(":8080", r))
}

func (la *LogAnalyzer) webHome(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Log Security Analyzer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        textarea { width: 100%; height: 200px; margin: 10px 0; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .alert { padding: 10px; margin: 10px 0; border-left: 4px solid #f39c12; background: #fff3cd; }
        .high { border-left-color: #dc3545; background: #f8d7da; }
        .medium { border-left-color: #ffc107; background: #fff3cd; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Log Security Analyzer</h1>
        <p>Paste your log entries below for security analysis:</p>
        <form method="POST" action="/analyze">
            <textarea name="logs" placeholder="Paste log entries here (JSON or plain text)..."></textarea><br>
            <button type="submit">Analyze Logs</button>
        </form>
    </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

func (la *LogAnalyzer) webAnalyze(w http.ResponseWriter, r *http.Request) {
	logs := r.FormValue("logs")
	if logs == "" {
		http.Error(w, "No logs provided", http.StatusBadRequest)
		return
	}

	// Reset alerts
	la.alerts = []SecurityAlert{}
	
	// Analyze each line
	lines := strings.Split(logs, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			la.analyzeLine(line, i+1)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_alerts": len(la.alerts),
		"alerts":       la.alerts,
	})
}

func (la *LogAnalyzer) webHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

func (la *LogAnalyzer) runDemo() {
	fmt.Println("🎯 Running Demo Analysis")
	fmt.Println("========================")
	
	// Create sample log entries with security issues
	sampleLogs := []string{
		`{"timestamp": "2024-05-24T10:00:00Z", "level": "ERROR", "message": "Failed login attempt for user admin", "ip": "192.168.1.100"}`,
		`{"timestamp": "2024-05-24T10:01:00Z", "level": "WARN", "message": "SQL query: SELECT * FROM users WHERE id=1 UNION SELECT * FROM passwords", "ip": "10.0.0.50"}`,
		`{"timestamp": "2024-05-24T10:02:00Z", "level": "INFO", "message": "File access request: ../../etc/passwd", "ip": "203.0.113.10"}`,
		`{"timestamp": "2024-05-24T10:03:00Z", "level": "ERROR", "message": "XSS attempt detected: <script>alert('hack')</script>", "ip": "198.51.100.20"}`,
		`{"timestamp": "2024-05-24T10:04:00Z", "level": "WARN", "message": "Rate limit exceeded: 429 Too Many Requests", "ip": "192.168.1.100"}`,
	}

	// Analyze sample logs
	for i, logLine := range sampleLogs {
		la.analyzeLine(logLine, i+1)
	}

	la.printResults()
	
	fmt.Println("\n💡 Demo completed! This demonstrates how the analyzer detects:")
	fmt.Println("   • Failed authentication attempts")
	fmt.Println("   • SQL injection patterns")
	fmt.Println("   • Directory traversal attempts")
	fmt.Println("   • Cross-site scripting (XSS)")
	fmt.Println("   • Rate limiting triggers")
}