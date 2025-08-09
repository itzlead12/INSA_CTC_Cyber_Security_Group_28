# INSA_CTC_Cyber_Security_Group_28
Group Members name - Yehualashet Temesgen 
                   - Oliyad Teshome
                   - Nebiyu Dawit 
                   - Amlakie Abebaw 
                   - Paulos Berihun
# WAF & API Security Gateway

A lightweight, scalable Web Application Firewall (WAF) combined with comprehensive API security features. Built using Nginx with ModSecurity and FastAPI, this solution is designed to provide robust, real-time protection for modern web applications and APIs, while maintaining ease of deployment and extensibility.

---
## Overview

In today’s digital landscape, web applications and APIs face an ever-growing spectrum of security threats including injection attacks, cross-site scripting, credential abuse, and denial-of-service attempts. This project addresses these challenges by delivering a unified security gateway that inspects incoming web traffic, filters malicious requests, enforces strict API validation and authentication, and monitors client behavior through rate limiting.
The system leverages the proven capabilities of ModSecurity paired with the OWASP Core Rule Set to block common attack vectors at the proxy level. Complementing this, a FastAPI backend applies business logic-based API security controls such as JSON schema validation and authentication mechanisms. All security-relevant data is logged in PostgreSQL to enable auditing, analytics, and incident response.
This architecture ensures layered defense while being flexible enough for diverse deployment scenarios — from small startups to enterprise environments — and provides a solid foundation for future enhancements like dashboards, alerting, and machine learning-based threat detection.

## Features

- Web Application Firewall (WAF):  
Utilizes Nginx with ModSecurity configured to enforce OWASP Core Rule Set (CRS), providing real-time inspection and blocking of common web attacks such as SQL Injection (SQLi), Cross-site Scripting (XSS), Remote Code Execution (RCE), and others.
      
- API Schema Validation:  
  Incoming API requests are validated against strongly-typed Pydantic models defined in FastAPI, ensuring only well-formed and expected data is processed, mitigating risks of malformed input attacks.

- Authentication & Authorization:  
  Supports both API key and JSON Web Token (JWT) authentication schemes, enabling secure access control tailored to various client needs and integration scenarios.

- Rate Limiting:  
  Implements client-specific rate limiting using PostgreSQL to track usage metrics, helping prevent abuse, brute-force attempts, and denial-of-service (DoS) attacks.

- Centralized Logging & Auditing:  
  All blocked requests, authentication failures, and rate limit violations are logged with context-rich metadata to PostgreSQL, facilitating security audits and forensic analysis.

- Modular and Extensible:  
  The modular design enables easy future expansion, such as incorporating dashboards, alerting mechanisms, additional authentication providers, or AI-driven anomaly detection.

- Containerized Deployment:  
  Fully containerized using Docker Compose, allowing rapid setup, consistent environments, and portability across development, staging, and production.

## Technology Stack

| Component            | Technology                           | Purpose                                          
| Reverse Proxy & WAF  | Nginx + ModSecurity with OWASP CRS   | Real-time web traffic filtering & attack blocking 
| API Backend          | FastAPI (Python)                     | API request validation, authentication, and rate limiting 
| Database             | PostgreSQL                           | Persistent storage for configuration, keys, logs, and rate limiting data 
| Containerization     | Docker Compose                       | Orchestrated deployment of multi-container environment 
