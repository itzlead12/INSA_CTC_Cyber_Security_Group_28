## Web Application Firewall (WAF) as a Service
**Problem It Solves**

Small and medium websites often lack affordable, easy-to-manage security against common web attacks. Traditional enterprise firewalls are either:

 - Too expensive to license and maintain.

 - Too complex for small teams to configure.


## This project provides an affordable, centralized WAF as a Service, designed to protect multiple client web applications, with:

- Easy onboarding (just point the domain DNS to the WAF).

- Custom rule management per client.

- Real-time analytics and blocking.

## Key Features

  - Attack Detection & Blocking

  - SQL Injection prevention

  - Cross-Site Scripting (XSS) filtering

  - User-Agent blocking (bots, scanners, crawlers)

  - Geo-blocking (restrict traffic by country)

  - Rate limiting (mitigate brute-force and DoS attempts)

## Multi-Tenant Support

Each client can register their app with its own domain.

Separate rules and logs per client.

 Reverse Proxy Protection

All requests go through the FastAPI WAF proxy.

Safe traffic is forwarded to the client’s actual app.

Malicious requests are blocked and logged.

 Centralized Dashboard (Django)

Admin UI for client and rule management.

Real-time log feed with WebSocket.

Analytics for blocked and allowed requests.

 Secure WAF-to-Django Communication

Rules and logs synchronized using API keys.

## Workflow
**Step-by-Step Flow**

 - User visits a protected client website (e.g., https://**********.com).

 - Request first reaches the FastAPI WAF proxy.

 - WAF fetches security rules for that client from the Django backend.

 - Request is analyzed against rules (SQLi, XSS, rate limit, etc.).

- If malicious, request is blocked → logged → sent to dashboard.

- If safe, request is forwarded to the client’s real app server.

 - Django dashboard updates in real-time with logs and analytics.

## Workflow Diagram
   <img width="275" height="956" alt="image" src="https://github.com/user-attachments/assets/1d5a606c-cdcb-42ee-b73b-c2ef9c060084" />


## Future Work


- Machine Learning & Anomaly Detection

- Detect unknown attack patterns with ML models.

- Adaptive learning from traffic patterns.

- TLS termination (HTTPS at WAF layer).

- Automatic certificate management (e.g., Let’s Encrypt).

- Kubernetes deployment with auto-scaling.

- High-availability load balancing.

- Alerts via Slack/Email/SMS.

- Client Self-Service

- Expose an API for clients to manage their own rules.

##  Tech Stack
- **Backend:** Django / FastAPI  
- **Web Server / Proxy:** Nginx  
- **Database:** PostgreSQL / MySQL  
- **Frontend Dashboard:** HTML + CSS(tailwind) + JS 
