# Multi-Client Web Application Firewall (WAF)  

A **Web Application Firewall (WAF)** that protects multiple client websites from common web threats such as SQL Injection, Cross-Site Scripting (XSS), and denial-of-service attempts.  
This project is designed as a **host-based WAF**, where multiple websites can register, get their own API key, and route traffic through the WAF for real-time protection, logging, and analytics.  

---

##  Features  

- **User Authentication**  
  - Secure signup and login with password hashing.  

- **Multi-Client Website Registration**  
  - Websites register to use the WAF.  
  - Each client receives a unique API key/token for authentication.  

- **Proxy / Request Forwarding**  
  - Clients configure DNS/proxy to route traffic through the WAF.  

- **Rule-Based Threat Detection**  
  - Detect and block common attacks (SQL Injection, XSS) using pattern-matching rules.  

- **Request Filtering & Blocking**  
  - Block malicious requests, forward safe ones to the real web server.  

- **Rate Limiting**  
  - Limit requests per IP to prevent abuse or DoS attacks.  

- **Logging & Reports**  
  - Store details of blocked requests:  
    - Client website  
    - Attacker IP  
    - Timestamp  
    - Rule triggered  

- **Admin Dashboard**  
  - Manage registered client websites.  
  - View traffic/attack stats per client.  
  - Review logs of blocked threats.  
  - Add/update detection rules.  

---

##  Problem It Solves  
Small and medium websites often lack affordable, easy-to-manage security against common web attacks. Traditional firewalls are either:  
- Too expensive 
- Complex to configure  
- Limited to one site only  

This WAF provides **affordable, centralized protection** for multiple sites, with easy onboarding and powerful analytics.  

---

##  Tech Stack
- **Backend:** Django / FastAPI  
- **Web Server / Proxy:** Nginx  
- **Database:** PostgreSQL / MySQL  
- **Authentication:** JWT / Session-based  
- **Frontend Dashboard:** React / HTML + CSS + JS  

