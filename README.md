# INSA_CTC_Cyber_Security_Group_28
Group Members name - Yehualashet Temesgen 
                   - Oliyad Teshome
                   - Nebiyu Dawit 
                   - Amlakie Abebaw 
                   - Paulos Berihun
# Web Application Firewall (WAF)

## Overview
This project is a modular and extensible Web Application Firewall (WAF) designed to inspect and filter incoming HTTP requests to protect web applications from a wide range of web-based attacks. It provides request inspection, rule-based filtering, behavior analysis, rate limiting, and logging capabilities. The WAF is configurable, easy to integrate, and designed to support both manual rule tuning and automated anomaly detection.

## Features

    * The WAF supports IP-based filtering, request method control, and User-Agent inspection. It allows administrators to define blacklists and whitelists to control traffic based on known patterns. Incoming HTTP requests are inspected using a rule-based engine that matches against known attack signatures, such as SQL injection, cross-site scripting (XSS), command injection, and path traversal, using configurable regular expressions stored in a JSON file.
    * Rate limiting is implemented to restrict the number of requests per IP address within a defined time window. The system logs all requests and blocked attempts, including metadata such as timestamp, source IP, and threat type. For critical events, notifications can be sent via email or command-line alerts.
    * The WAF can operate in a learning mode, where suspicious patterns are detected but not blocked, allowing fine-tuning of detection rules and minimizing false positives. Real-time detection capabilities can be extended by integrating external rule feeds (such as Snort or Suricata signatures) and threat intelligence APIs (e.g., AbuseIPDB).
     * Geo-blocking is supported using IP-based geolocation, allowing the system to block requests originating from specific countries. Anomaly detection features help identify abnormal behaviors such as unexpected HTTP methods, high request frequency, or suspicious payload sizes. The WAF also includes CSRF token injection and validation, helping detect missing or reused tokens to prevent forgery attacks.
      * Headers are inspected to ensure essential security headers (such as Content-Security-Policy and X-Frame-Options) are present, and to detect spoofed values in headers like X-Forwarded-For. All components are configurable through a centralized settings file, allowing specific protections to be enabled or disabled as needed.
      * The project includes a CLI-based monitoring interface and a minimal web-based dashboard for real-time log viewing and statistics. It is written in Python using Flask and standard libraries, making it lightweight and easy to deploy. Optional support for asynchronous detection and future integration with modern APIs or dashboards is planned.

## Technologies Used

- Python
- Flask
- Regex (`re`)
- Flask-Limiter (rate limiting)
- Logging
- JSON-based configuration
- GeoIP2 (for geolocation-based filtering)
- Optional threat intelligence APIs

