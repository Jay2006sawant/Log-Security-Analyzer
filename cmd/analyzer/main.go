package main

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.Info("Starting Log Security Analyzer")

	fmt.Println("Log Security Analyzer started...")

	sampleLog := "2024-01-01 ERROR: Failed login attempt from 192.168.1.100"
	analyzeLog(sampleLog)

	logrus.Info("Analysis complete")
}

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
