# Security Policy

## Supported Versions

This project is designed for demonstration purposes and contains intentionally vulnerable dependencies.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

This project intentionally includes vulnerable dependencies for demonstration of Renovate's security update capabilities:

- `gopkg.in/yaml.v2 v2.2.8` - CVE-2022-28948 (HIGH severity)
- `github.com/go-chi/chi v4.1.2` - CVE-2023-49568 (MEDIUM severity)

These vulnerabilities are expected and will be automatically updated by Renovate when configured.

For any other security concerns, please create an issue in this repository.