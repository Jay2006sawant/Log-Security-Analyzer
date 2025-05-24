package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// Middleware to check for Authorization header
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			logrus.Warn("Missing Auth Header")
			http.Error(w, "Missing Auth Header", http.StatusUnauthorized)
			return
		}
		// Optional: validate the token here if needed
		next.ServeHTTP(w, r)
	})
}

// HTTP handler to receive a log line and analyze it
func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}
	logLine := string(bodyBytes)
	analyzeLog(logLine)

	fmt.Fprintf(w, "Log analyzed: %s\n", logLine)
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.Info("Starting Log Security Analyzer HTTP server")

	http.Handle("/analyze", authMiddleware(http.HandlerFunc(analyzeHandler)))

	fmt.Println("Server running on http://localhost:7000")
	logrus.Info("Listening on :7000")
	http.ListenAndServe(":7000", nil)
}

// Your existing analyzeLog function
func analyzeLog(logLine string) {
	logrus.WithField("log", logLine).Info("Analyzing log entry")

	if strings.Contains(strings.ToLower(logLine), "failed login") {
		logrus.WithFields(logrus.Fields{
			"severity": "HIGH",
			"type":     "security_event",
		}).Warn("Detected failed login attempt")
		fmt.Printf("🚨 SECURITY ALERT: %s\n", logLine)
	} else {
		logrus.Debug("Log entry appears normal")
		fmt.Printf("✅ Normal log: %s\n", logLine)
	}
}

